// Package db manages PostgreSQL connections, schema migrations and the
// privileges of the least-privilege runtime role.
package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serxan22/delil/migrations"
)

// Options tune the connection pool.
type Options struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	HealthCheckPeriod time.Duration
	ApplicationName   string
}

// Connect opens a connection pool and checks that the server is reachable.
func Connect(ctx context.Context, url string, opts Options) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("db: invalid database URL: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.MaxConnLifetime
	}
	if opts.HealthCheckPeriod > 0 {
		cfg.HealthCheckPeriod = opts.HealthCheckPeriod
	}
	name := opts.ApplicationName
	if name == "" {
		name = "delil"
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	// Timestamps are always handled in UTC.
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}

// Migration is one embedded schema migration.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// AppliedMigration describes a migration recorded in the database.
type AppliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt time.Time
}

var migrationFile = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// Migrations returns the embedded migrations in order.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationFile.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("db: migration file %q does not match NNNN_name.sql", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(migrations.FS, e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{Version: version, Name: m[2], SQL: string(body), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("db: duplicate migration version %d", out[i].Version)
		}
	}
	return out, nil
}

const migrationsTable = `CREATE TABLE IF NOT EXISTS delil_schema_migrations (
    version    integer PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// migrationLockKey is an arbitrary constant identifying the migration lock.
const migrationLockKey int64 = 0x64656c696c // "delil"

// ErrMigrationModified means an applied migration file was edited afterwards.
var ErrMigrationModified = errors.New("db: an applied migration was modified")

// Migrate applies pending migrations. It holds a session-level advisory lock,
// so concurrent instances wait instead of racing, runs each migration in its
// own transaction, and refuses to continue if an applied migration's checksum
// changed.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]Migration, error) {
	all, err := Migrations()
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return nil, fmt.Errorf("db: acquire migration lock: %w", err)
	}
	defer func() {
		// Use a fresh context: the lock must be released even if ctx is done.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, migrationsTable); err != nil {
		return nil, fmt.Errorf("db: create migrations table: %w", err)
	}
	applied, err := appliedMigrations(ctx, conn.Conn())
	if err != nil {
		return nil, err
	}
	var ran []Migration
	for _, m := range all {
		if a, ok := applied[m.Version]; ok {
			if a.Checksum != m.Checksum {
				return ran, fmt.Errorf("%w: %04d_%s (applied checksum %s, file checksum %s)",
					ErrMigrationModified, m.Version, m.Name, short(a.Checksum), short(m.Checksum))
			}
			continue
		}
		err := pgx.BeginFunc(ctx, conn.Conn(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO delil_schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
				m.Version, m.Name, m.Checksum)
			return err
		})
		if err != nil {
			return ran, fmt.Errorf("db: migration %04d_%s failed: %w", m.Version, m.Name, err)
		}
		ran = append(ran, m)
	}
	return ran, nil
}

// short abbreviates a checksum for messages. The stored value may have been
// tampered with, so its length is not assumed.
func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func appliedMigrations(ctx context.Context, conn *pgx.Conn) (map[int]AppliedMigration, error) {
	rows, err := conn.Query(ctx, `SELECT version, name, checksum, applied_at FROM delil_schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int]AppliedMigration)
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, err
		}
		out[a.Version] = a
	}
	return out, rows.Err()
}

// MigrationState is used by readiness checks and `delil-server migrate status`.
type MigrationState struct {
	Migration
	Applied   bool
	AppliedAt time.Time
	Modified  bool
}

// Status compares embedded migrations with the database.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]MigrationState, error) {
	all, err := Migrations()
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('delil_schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	applied := map[int]AppliedMigration{}
	if exists {
		if applied, err = appliedMigrations(ctx, conn.Conn()); err != nil {
			return nil, err
		}
	}
	out := make([]MigrationState, 0, len(all))
	for _, m := range all {
		st := MigrationState{Migration: m}
		if a, ok := applied[m.Version]; ok {
			st.Applied, st.AppliedAt, st.Modified = true, a.AppliedAt, a.Checksum != m.Checksum
		}
		out = append(out, st)
	}
	return out, nil
}

// UpToDate reports whether every embedded migration is applied unmodified.
func UpToDate(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	states, err := Status(ctx, pool)
	if err != nil {
		return false, err
	}
	for _, s := range states {
		if !s.Applied || s.Modified {
			return false, nil
		}
	}
	return true, nil
}

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Runtime privileges. The runtime role may read everything it needs and
// append audit records, but it cannot UPDATE, DELETE or TRUNCATE events,
// checkpoints or streams' identity, and it cannot change the schema.
var runtimeGrants = []string{
	`GRANT USAGE ON SCHEMA public TO %s`,
	`GRANT SELECT ON delil_schema_migrations TO %s`,
	`GRANT SELECT, INSERT ON audit_events, checkpoints, checkpoint_anchors TO %s`,
	`GRANT SELECT, INSERT, UPDATE ON tenants, projects, users, api_keys, signing_keys, audit_streams,
	        verification_runs, stream_verifications, exports TO %s`,
	`GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, idempotency_keys TO %s`,
}

// GrantRuntimePrivileges grants the least-privilege set to role. It must be
// run by the schema owner after migrations and is idempotent.
func GrantRuntimePrivileges(ctx context.Context, pool *pgxpool.Pool, role string) error {
	if !roleName.MatchString(role) {
		return fmt.Errorf("db: invalid role name %q", role)
	}
	ident := pgx.Identifier{role}.Sanitize()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, g := range runtimeGrants {
			if _, err := tx.Exec(ctx, fmt.Sprintf(g, ident)); err != nil {
				return fmt.Errorf("db: grant to %s: %w", role, err)
			}
		}
		return nil
	})
}

// WithAdvisoryLock runs fn while holding a session-level advisory lock if it
// can be acquired immediately. It reports whether fn ran. Used to make sure
// only one instance runs a periodic job at a time.
func WithAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, key int64, fn func(context.Context) error) (bool, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
		return false, err
	}
	if !locked {
		return false, nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", key)
	}()
	return true, fn(ctx)
}
