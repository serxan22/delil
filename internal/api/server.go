// Package api is DƏLİL's REST API. Handlers are thin: they authenticate,
// authorize by scope, validate input and delegate to the audit,
// verification, export and key services.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/serxan22/delil/api"
	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/checkpoint"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/db"
	"github.com/serxan22/delil/internal/export"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/metrics"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/verification"
)

// Deps are the services the API uses.
type Deps struct {
	Config      *config.Config
	Store       *store.Store
	Keys        *keys.Manager
	Appender    *audit.Appender
	Verifier    *verification.Service
	Exports     *export.Service
	Checkpoints *checkpoint.Service
	Metrics     *metrics.Metrics
	Logger      *slog.Logger
	Version     string
}

// Server serves the API.
type Server struct {
	cfg         *config.Config
	store       *store.Store
	keys        *keys.Manager
	appender    *audit.Appender
	verifier    *verification.Service
	exports     *export.Service
	checkpoints *checkpoint.Service
	metrics     *metrics.Metrics
	log         *slog.Logger
	version     string
	now         func() time.Time

	mux          *http.ServeMux
	corsOrigins  map[string]bool
	apiLimiter   *auth.Limiter
	loginByIP    *auth.Limiter
	loginByEmail *auth.Limiter

	touchMu sync.Mutex
	touched map[string]time.Time
}

// New builds the server and its routes.
func New(d Deps) *Server {
	s := &Server{
		cfg: d.Config, store: d.Store, keys: d.Keys, appender: d.Appender, verifier: d.Verifier,
		exports: d.Exports, checkpoints: d.Checkpoints, metrics: d.Metrics, log: d.Logger, version: d.Version,
		now: time.Now, mux: http.NewServeMux(), corsOrigins: map[string]bool{}, touched: map[string]time.Time{},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	for _, o := range d.Config.CORSOrigins {
		s.corsOrigins[o] = true
	}
	s.apiLimiter = auth.NewLimiter(d.Config.RateLimitRPS, d.Config.RateLimitBurst)
	if d.Config.LoginRateLimit > 0 {
		s.loginByIP = auth.NewWindowLimiter(d.Config.LoginRateLimit, 15*time.Minute)
		s.loginByEmail = auth.NewWindowLimiter(d.Config.LoginRateLimit, 15*time.Minute)
	}
	s.routes()
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.middleware(s.mux) }

// MetricsHandler serves Prometheus metrics, optionally behind a bearer token.
func (s *Server) MetricsHandler() http.Handler {
	h := promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{})
	if s.cfg.MetricsToken == "" {
		return h
	}
	want := auth.HashToken(s.cfg.MetricsToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !auth.EqualHash(want[:], auth.HashToken(tok)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type requirement struct {
	scope       string
	project     bool
	sessionOnly bool
}

func project(scope string) requirement     { return requirement{scope: scope, project: true} }
func tenantScope(scope string) requirement { return requirement{scope: scope, sessionOnly: true} }

var session = requirement{sessionOnly: true}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *Principal) error

func (s *Server) handle(pattern string, req requirement, h handlerFunc) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		setPrincipal(r, p)
		if req.sessionOnly && p.Kind != KindSession {
			s.writeError(w, r, forbidden("this operation is only available to dashboard users"))
			return
		}
		if req.project {
			if err := s.resolveProject(r, p); err != nil {
				s.writeError(w, r, err)
				return
			}
		}
		if req.scope != "" && !p.Can(req.scope) {
			s.writeError(w, r, forbidden("missing required scope %q", req.scope))
			return
		}
		if ok, retry := s.apiLimiter.Allow(p.RateKey()); !ok {
			e := errorf(http.StatusTooManyRequests, "rate_limited", "too many requests")
			e.RetryAfter = retry
			s.writeError(w, r, e)
			return
		}
		if err := h(w, r, p); err != nil {
			s.writeError(w, r, err)
		}
	})
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /{$}", s.handleRoot)
	m.HandleFunc("GET /health", s.handleHealth)
	m.HandleFunc("GET /ready", s.handleReady)
	m.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
	if s.cfg.MetricsAddr == "" && s.metrics != nil {
		m.Handle("GET /metrics", s.MetricsHandler())
	}

	m.HandleFunc("POST /v1/auth/login", s.handleLogin)
	s.handle("POST /v1/auth/logout", session, s.handleLogout)
	s.handle("GET /v1/auth/session", session, s.handleSession)
	s.handle("POST /v1/auth/password", session, s.handleChangePassword)

	s.handle("GET /v1/projects", tenantScope(auth.ScopeEventsRead), s.handleListProjects)
	s.handle("POST /v1/projects", tenantScope(auth.ScopeTenantManage), s.handleCreateProject)
	s.handle("GET /v1/users", tenantScope(auth.ScopeTenantManage), s.handleListUsers)
	s.handle("POST /v1/users", tenantScope(auth.ScopeTenantManage), s.handleCreateUser)

	s.handle("GET /v1/project", project(""), s.handleGetProject)
	s.handle("PATCH /v1/project", project(auth.ScopeProjectManage), s.handleUpdateProject)
	s.handle("GET /v1/overview", project(auth.ScopeEventsRead), s.handleOverview)

	s.handle("POST /v1/events", project(auth.ScopeEventsWrite), s.handleRecordEvent)
	s.handle("POST /v1/events/batch", project(auth.ScopeEventsWrite), s.handleRecordBatch)
	s.handle("GET /v1/events", project(auth.ScopeEventsRead), s.handleListEvents)
	s.handle("GET /v1/events/{id}", project(auth.ScopeEventsRead), s.handleGetEvent)
	s.handle("GET /v1/events/{id}/verify", project(auth.ScopeVerify), s.handleVerifyEvent)

	s.handle("GET /v1/streams", project(auth.ScopeEventsRead), s.handleListStreams)
	s.handle("GET /v1/streams/{name}", project(auth.ScopeEventsRead), s.handleGetStream)
	s.handle("GET /v1/streams/{name}/chain", project(auth.ScopeEventsRead), s.handleChain)
	s.handle("POST /v1/streams/{name}/verify", project(auth.ScopeVerify), s.handleVerifyStream)
	s.handle("GET /v1/streams/{name}/checkpoints", project(auth.ScopeEventsRead), s.handleListCheckpoints)
	s.handle("POST /v1/streams/{name}/checkpoints", project(auth.ScopeVerify), s.handleCreateCheckpoint)

	s.handle("POST /v1/verify", project(auth.ScopeVerify), s.handleVerifyProject)
	s.handle("GET /v1/verification-runs", project(auth.ScopeEventsRead), s.handleListRuns)
	s.handle("GET /v1/verification-runs/{id}", project(auth.ScopeEventsRead), s.handleGetRun)

	s.handle("POST /v1/exports", project(auth.ScopeExports), s.handleCreateExport)
	s.handle("GET /v1/exports", project(auth.ScopeExports), s.handleListExports)
	s.handle("GET /v1/exports/{id}", project(auth.ScopeExports), s.handleGetExport)
	s.handle("GET /v1/exports/{id}/download", project(auth.ScopeExports), s.handleDownloadExport)

	s.handle("POST /v1/api-keys", project(auth.ScopeAPIKeysManage), s.handleCreateAPIKey)
	s.handle("GET /v1/api-keys", project(auth.ScopeAPIKeysManage), s.handleListAPIKeys)
	s.handle("DELETE /v1/api-keys/{id}", project(auth.ScopeAPIKeysManage), s.handleRevokeAPIKey)

	s.handle("GET /v1/signing-keys", project(auth.ScopeKeysRead), s.handleListSigningKeys)
	s.handle("GET /v1/signing-keys/export", project(auth.ScopeKeysRead), s.handleExportSigningKeys)
	s.handle("POST /v1/signing-keys/rotate", project(auth.ScopeKeysRotate), s.handleRotateSigningKey)
	s.handle("POST /v1/signing-keys/{id}/revoke", project(auth.ScopeKeysRotate), s.handleRevokeSigningKey)

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, notFound("route"))
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        "DƏLİL",
		"description": "Cryptographically verifiable audit infrastructure",
		"version":     s.version,
		"openapi":     "/openapi.yaml",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.version})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	checks := map[string]string{"database": "ok", "migrations": "ok"}
	ready := true
	if err := s.store.Pool.Ping(ctx); err != nil {
		checks["database"], ready = "unreachable", false
	} else if ok, err := db.UpToDate(ctx, s.store.Pool); err != nil || !ok {
		checks["migrations"], ready = "pending or modified", false
	}
	status, code := "ready", http.StatusOK
	if !ready {
		status, code = "not_ready", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "checks": checks})
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(api.OpenAPI)
}

// touch records last-used timestamps at most once per minute per credential.
func (s *Server) touch(key string, fn func(context.Context, time.Time) error) {
	now := s.now()
	s.touchMu.Lock()
	if last, ok := s.touched[key]; ok && now.Sub(last) < time.Minute {
		s.touchMu.Unlock()
		return
	}
	s.touched[key] = now
	if len(s.touched) > 100000 {
		s.touched = map[string]time.Time{key: now}
	}
	s.touchMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fn(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Warn("updating last-used timestamp failed", "error", err)
		}
	}()
}

// trigger classifies who started an operation, for verification history.
func trigger(r *http.Request, p *Principal) verification.Trigger {
	kind := "api"
	switch {
	case p.Kind == KindSession:
		kind = "dashboard"
	case r.Header.Get("Delil-Client") == "cli":
		kind = "cli"
	}
	return verification.Trigger{Kind: kind, By: p.Actor()}
}
