// Package app wires DƏLİL's services together from configuration. The server
// binary and the API integration tests use the same wiring.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serxan22/delil/internal/api"
	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/checkpoint"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/db"
	"github.com/serxan22/delil/internal/export"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/metrics"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/verification"
)

// App holds every service.
type App struct {
	Config      *config.Config
	Log         *slog.Logger
	Pool        *pgxpool.Pool
	Store       *store.Store
	Keys        *keys.Manager
	Appender    *audit.Appender
	Verifier    *verification.Service
	Exports     *export.Service
	Checkpoints *checkpoint.Service
	Metrics     *metrics.Metrics
	API         *api.Server
	Version     string
}

// NewLogger builds the structured logger.
func NewLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h).With("service", "delil")
}

// ResolveMasterKey returns the configured master key. In development only, a
// missing key is generated once and persisted in the data directory.
func ResolveMasterKey(cfg *config.Config, log *slog.Logger) ([]byte, error) {
	if cfg.MasterKey != nil {
		return cfg.MasterKey, nil
	}
	if !cfg.IsDevelopment() {
		return nil, errors.New("a master key is required (DELIL_MASTER_KEY or DELIL_MASTER_KEY_FILE)")
	}
	path := filepath.Join(cfg.DataDir, "master.key")
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // operator-configured path
		return config.DecodeMasterKey(strings.TrimSpace(string(data)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, keys.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	log.Warn("DEVELOPMENT ONLY: generated a master key and stored it next to the data; "+
		"set DELIL_MASTER_KEY from a secret manager in production", "path", path)
	return key, nil
}

// NewProvider builds the configured key provider.
func NewProvider(cfg *config.Config, log *slog.Logger) (keys.Provider, []keys.Provider, error) {
	switch cfg.KeyProvider {
	case "file":
		p, err := keys.NewFileProvider(cfg.KeyDir)
		return p, nil, err
	default:
		mk, err := ResolveMasterKey(cfg, log)
		if err != nil {
			return nil, nil, err
		}
		p, err := keys.NewLocalProvider(mk)
		if err != nil {
			return nil, nil, err
		}
		var others []keys.Provider
		if cfg.KeyDir != "" {
			if fp, err := keys.NewFileProvider(cfg.KeyDir); err == nil {
				others = append(others, fp)
			}
		}
		return p, others, nil
	}
}

// Migrate applies migrations with the migration connection and grants the
// runtime role its privileges.
func Migrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := db.Connect(ctx, cfg.MigrationDatabaseURL, db.Options{MaxConns: 2, ApplicationName: "delil-migrate"})
	if err != nil {
		return err
	}
	defer pool.Close()
	ran, err := db.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	for _, m := range ran {
		log.Info("migration applied", "version", m.Version, "name", m.Name)
	}
	if cfg.DBAppRole != "" {
		if err := db.GrantRuntimePrivileges(ctx, pool, cfg.DBAppRole); err != nil {
			return err
		}
		log.Info("runtime privileges granted", "role", cfg.DBAppRole)
	}
	return nil
}

// New connects to the database and builds the services.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, version string) (*App, error) {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, db.Options{MaxConns: cfg.DBMaxConns, ApplicationName: "delil"})
	if err != nil {
		return nil, err
	}
	a, err := Build(cfg, log, version, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return a, nil
}

// Build wires services on an existing pool.
func Build(cfg *config.Config, log *slog.Logger, version string, pool *pgxpool.Pool) (*App, error) {
	st := store.New(pool)
	provider, others, err := NewProvider(cfg, log)
	if err != nil {
		return nil, err
	}
	km := keys.NewManager(st, provider, others...)
	vs := verification.NewService(st, km, version)
	var anchors []checkpoint.Anchor
	if cfg.AnchorDir != "" {
		anchors = append(anchors, checkpoint.FileAnchor{Dir: cfg.AnchorDir})
	}
	cps := checkpoint.NewService(st, km, log, anchors...)
	xs, err := export.NewService(st, km, vs, export.Options{Dir: cfg.ExportDir, TTL: cfg.ExportTTL, Version: version, Logger: log})
	if err != nil {
		return nil, fmt.Errorf("export directory %s: %w", cfg.ExportDir, err)
	}
	m := metrics.New(version, headSource{st})
	a := &App{
		Config: cfg, Log: log, Pool: pool, Store: st, Keys: km, Verifier: vs, Exports: xs, Checkpoints: cps,
		Metrics: m, Version: version,
		Appender: audit.NewAppender(st, km, audit.AppenderOptions{MaxStreamsPerProject: cfg.MaxStreamsPerProject,
			IdempotencyTTL: cfg.IdempotencyTTL}),
	}
	a.API = api.New(api.Deps{Config: cfg, Store: st, Keys: km, Appender: a.Appender, Verifier: vs, Exports: xs,
		Checkpoints: cps, Metrics: m, Logger: log, Version: version})
	return a, nil
}

// Close releases resources.
func (a *App) Close() { a.Pool.Close() }

type headSource struct{ st *store.Store }

func (h headSource) StreamHeads(ctx context.Context, limit int) ([]metrics.StreamHead, error) {
	rows, err := h.st.Pool.Query(ctx, `SELECT project_id, name, head_sequence FROM audit_streams ORDER BY project_id, name LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []metrics.StreamHead
	for rows.Next() {
		var sh metrics.StreamHead
		if err := rows.Scan(&sh.ProjectID, &sh.Stream, &sh.Sequence); err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

// Advisory lock keys for singleton background jobs.
const (
	lockCheckpoints int64 = 0x64656c01
	lockVerify      int64 = 0x64656c02
	lockCleanup     int64 = 0x64656c03
)

// RunWorkers runs the background jobs until ctx is cancelled. Jobs that must
// not run concurrently across instances take PostgreSQL advisory locks.
func (a *App) RunWorkers(ctx context.Context) {
	go a.Exports.Run(ctx, 5*time.Second)
	go a.every(ctx, a.Config.CheckpointPoll, "checkpoints", lockCheckpoints, func(ctx context.Context) error {
		n, err := a.Checkpoints.RunOnce(ctx, a.Config.CheckpointEvery, a.Config.CheckpointMaxAge)
		if n > 0 {
			a.Metrics.CheckpointsCreated.Add(float64(n))
			a.Log.Info("checkpoints created", "count", n)
		}
		return err
	})
	if a.Config.VerifyInterval > 0 {
		go a.every(ctx, a.Config.VerifyInterval, "scheduled verification", lockVerify, a.verifyAll)
	}
	go a.every(ctx, 10*time.Minute, "cleanup", lockCleanup, a.cleanup)
}

func (a *App) every(ctx context.Context, interval time.Duration, name string, lock int64, fn func(context.Context) error) {
	if interval <= 0 {
		return
	}
	// A short initial delay lets the server finish starting.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ran, err := db.WithAdvisoryLock(ctx, a.Pool, lock, fn)
		if err != nil && ctx.Err() == nil {
			a.Log.Error("background job failed", "job", name, "error", err)
		} else if !ran {
			a.Log.Debug("background job skipped; another instance holds the lock", "job", name)
		}
		timer.Reset(interval)
	}
}

func (a *App) verifyAll(ctx context.Context) error {
	projects, err := a.Store.ListAllProjects(ctx)
	if err != nil {
		return err
	}
	for _, p := range projects {
		pr, err := a.Verifier.VerifyProject(ctx, p.TenantID, p.ID)
		if err != nil {
			a.Log.Error("scheduled verification failed to run", "project_id", p.ID, "error", err)
			continue
		}
		if pr.StreamsChecked == 0 {
			continue
		}
		if _, err := a.Verifier.RecordProject(ctx, p.TenantID, p.ID, pr, verification.Trigger{Kind: "schedule", By: "system"}); err != nil {
			a.Log.Error("recording scheduled verification failed", "project_id", p.ID, "error", err)
		}
		result := "valid"
		if !pr.Valid {
			result = "invalid"
			a.Metrics.VerificationFailures.WithLabelValues("project").Inc()
			a.Log.Error("INTEGRITY VERIFICATION FAILED", "project_id", p.ID, "failures", pr.FailureCount)
		}
		a.Metrics.Verifications.WithLabelValues("project", result).Inc()
	}
	return nil
}

func (a *App) cleanup(ctx context.Context) error {
	now := time.Now()
	if n, err := a.Store.DeleteExpiredSessions(ctx, now.Add(-24*time.Hour)); err != nil {
		return err
	} else if n > 0 {
		a.Log.Info("expired sessions removed", "count", n)
	}
	if n, err := a.Store.DeleteExpiredIdempotency(ctx, now); err != nil {
		return err
	} else if n > 0 {
		a.Log.Debug("expired idempotency keys removed", "count", n)
	}
	if n, err := a.Exports.Cleanup(ctx); err != nil {
		return err
	} else if n > 0 {
		a.Log.Info("expired exports removed", "count", n)
	}
	return nil
}
