package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/app"
	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testdb"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

type harness struct {
	t   *testing.T
	app *app.App
	srv *httptest.Server
}

func newHarness(t *testing.T, mutate ...func(*config.Config)) *harness {
	t.Helper()
	d := testdb.New(t)
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	cfg := &config.Config{
		Env: config.EnvDevelopment, KeyProvider: "local", MasterKey: mk, ExportDir: t.TempDir(),
		MaxEventBytes: 64 * 1024, MaxBatchEvents: 50, MaxRequestBytes: 1 << 20, MaxStreamsPerProject: 100,
		RateLimitRPS: 1000, RateLimitBurst: 1000, LoginRateLimit: 10, SessionTTL: time.Hour,
		IdempotencyTTL: time.Hour, ExportTTL: time.Hour, CheckpointEvery: 1000,
	}
	for _, m := range mutate {
		m(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := app.Build(cfg, log, "test", d.Pool)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.API.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, app: a, srv: srv}
}

type tenantFixture struct {
	TenantID, ProjectID string
	Key                 string
}

// tenant creates an organization, a project, a signing key, an admin user and
// an API key with the given scopes.
func (h *harness) tenant(slug string, scopes ...string) tenantFixture {
	h.t.Helper()
	if len(scopes) == 0 {
		scopes = auth.APIKeyScopes
	}
	ctx := context.Background()
	f := tenantFixture{TenantID: id.New(id.Tenant), ProjectID: id.New(id.Project)}
	now := time.Now().UTC()
	err := h.app.Store.InTx(ctx, func(tx pgx.Tx) error {
		if err := h.app.Store.CreateTenant(ctx, tx, store.Tenant{ID: f.TenantID, Slug: slug, Name: slug, CreatedAt: now}); err != nil {
			return err
		}
		if err := h.app.Store.CreateProject(ctx, tx, store.Project{ID: f.ProjectID, TenantID: f.TenantID, Slug: "main", Name: "Main", CreatedAt: now}); err != nil {
			return err
		}
		_, err := h.app.Keys.CreateInitialKey(ctx, tx, f.TenantID, f.ProjectID)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	f.Key = h.apiKey(f, scopes...)
	return f
}

func (h *harness) apiKey(f tenantFixture, scopes ...string) string {
	h.t.Helper()
	raw, lookup, hash := auth.NewAPIKey()
	err := h.app.Store.CreateAPIKey(context.Background(), h.app.Pool, store.APIKey{ID: id.New(id.APIKey), TenantID: f.TenantID,
		ProjectID: f.ProjectID, Name: "test", LookupID: lookup, SecretHash: hash[:], Scopes: scopes, CreatedAt: time.Now()})
	if err != nil {
		h.t.Fatal(err)
	}
	return raw
}

func (h *harness) user(f tenantFixture, email, role, password string) {
	h.t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.app.Store.CreateUser(context.Background(), h.app.Pool, store.User{ID: id.New(id.User), TenantID: f.TenantID,
		Email: email, DisplayName: email, PasswordHash: hash, Role: role, CreatedAt: time.Now()}); err != nil {
		h.t.Fatal(err)
	}
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r response) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("response is not JSON (%d): %s", r.Status, r.Body)
	}
	return m
}

func (r response) code(t *testing.T) string {
	t.Helper()
	if e, ok := r.json(t)["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return ""
}

func (h *harness) do(method, path, token string, body any, headers ...string) response {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return response{Status: resp.StatusCode, Header: resp.Header, Body: data}
}

func event(stream string, i int) map[string]any {
	return map[string]any{
		"stream": stream, "action": "contract.updated",
		"actor":    map[string]any{"type": "user", "id": fmt.Sprintf("user_%d", i%3)},
		"resource": map[string]any{"type": "contract", "id": fmt.Sprintf("contract_%d", i)},
		"before":   map[string]any{"version": i}, "after": map[string]any{"version": i + 1},
	}
}

func (h *harness) record(f tenantFixture, stream string, n int) []string {
	h.t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		r := h.do("POST", "/v1/events", f.Key, event(stream, i))
		if r.Status != http.StatusCreated {
			h.t.Fatalf("record: %d %s", r.Status, r.Body)
		}
		ids = append(ids, r.json(h.t)["id"].(string))
	}
	return ids
}

func TestTenantIsolation(t *testing.T) {
	h := newHarness(t)
	a := h.tenant("alpha")
	b := h.tenant("bravo")
	aIDs := h.record(a, "contracts", 3)
	h.record(b, "contracts", 2)

	// Same stream name in both tenants: each sees only its own events.
	for _, tc := range []struct {
		f    tenantFixture
		want int
	}{{a, 3}, {b, 2}} {
		r := h.do("GET", "/v1/events?stream=contracts", tc.f.Key, nil)
		if n := len(r.json(t)["data"].([]any)); n != tc.want {
			t.Fatalf("tenant sees %d events, want %d", n, tc.want)
		}
	}
	// Direct access to another tenant's resources is indistinguishable from
	// a missing resource.
	paths := []string{
		"/v1/events/" + aIDs[0], "/v1/events/" + aIDs[0] + "/verify",
	}
	for _, p := range paths {
		if r := h.do("GET", p, b.Key, nil); r.Status != http.StatusNotFound {
			t.Errorf("GET %s from another tenant: %d %s", p, r.Status, r.Body)
		}
	}
	// Exports of tenant A cannot be read or downloaded by tenant B.
	x := h.do("POST", "/v1/exports", a.Key, map[string]any{"stream": "contracts"}).json(t)
	for _, p := range []string{"/v1/exports/" + x["id"].(string), "/v1/exports/" + x["id"].(string) + "/download"} {
		if r := h.do("GET", p, b.Key, nil); r.Status != http.StatusNotFound {
			t.Errorf("GET %s from another tenant: %d", p, r.Status)
		}
	}
	// A dashboard user of tenant B cannot select tenant A's project.
	h.user(b, "bob@bravo.example", auth.RoleAdmin, "bravo-password-123")
	tok := h.do("POST", "/v1/auth/login", "", map[string]any{"email": "bob@bravo.example", "password": "bravo-password-123"}).json(t)["token"].(string)
	if r := h.do("GET", "/v1/events", tok, nil, "Delil-Project", a.ProjectID); r.Status != http.StatusNotFound {
		t.Fatalf("cross-tenant project selection: %d %s", r.Status, r.Body)
	}
	if r := h.do("GET", "/v1/events", tok, nil, "Delil-Project", b.ProjectID); r.Status != http.StatusOK {
		t.Fatalf("own project: %d %s", r.Status, r.Body)
	}
	// API keys of B cannot list A's keys or rotate A's signing keys.
	keysA := h.do("GET", "/v1/signing-keys", a.Key, nil).json(t)["data"].([]any)
	keyID := keysA[0].(map[string]any)["id"].(string)
	if r := h.do("POST", "/v1/signing-keys/"+keyID+"/revoke", b.Key, map[string]any{"reason": "attack"}); r.Status != http.StatusNotFound {
		t.Fatalf("revoking another tenant's key: %d %s", r.Status, r.Body)
	}
	if r := h.do("GET", "/v1/streams/contracts", a.Key, nil).json(t); r["headSequence"].(float64) != 3 {
		t.Fatal("tenant A's stream must be untouched")
	}
}

func TestScopes(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("scopes")
	writer := h.apiKey(f, auth.ScopeEventsWrite)
	reader := h.apiKey(f, auth.ScopeEventsRead)
	if r := h.do("POST", "/v1/events", writer, event("s", 1)); r.Status != http.StatusCreated {
		t.Fatalf("writer: %d", r.Status)
	}
	checks := []struct {
		method, path, key string
		body              any
		want              int
	}{
		{"GET", "/v1/events", writer, nil, 403},
		{"POST", "/v1/events", reader, event("s", 2), 403},
		{"POST", "/v1/streams/s/verify", reader, nil, 403},
		{"POST", "/v1/exports", reader, map[string]any{"stream": "s"}, 403},
		{"POST", "/v1/signing-keys/rotate", reader, nil, 403},
		{"GET", "/v1/api-keys", reader, nil, 403},
		{"GET", "/v1/events", reader, nil, 200},
		{"GET", "/v1/projects", reader, nil, 403}, // tenant routes are for dashboard users
	}
	for _, c := range checks {
		if r := h.do(c.method, c.path, c.key, c.body); r.Status != c.want {
			t.Errorf("%s %s: got %d want %d (%s)", c.method, c.path, r.Status, c.want, r.Body)
		}
	}
	// An API key cannot mint a key with scopes it does not have.
	manager := h.apiKey(f, auth.ScopeAPIKeysManage, auth.ScopeEventsRead)
	if r := h.do("POST", "/v1/api-keys", manager, map[string]any{"name": "x", "scopes": []string{"events:write"}}); r.Status != 403 {
		t.Fatalf("privilege escalation: %d %s", r.Status, r.Body)
	}
	created := h.do("POST", "/v1/api-keys", manager, map[string]any{"name": "ro", "scopes": []string{"events:read"}})
	if created.Status != 201 || !strings.HasPrefix(created.json(t)["secret"].(string), "dlk_") {
		t.Fatalf("create key: %d %s", created.Status, created.Body)
	}
	// The secret is never returned again.
	if bytes.Contains(h.do("GET", "/v1/api-keys", manager, nil).Body, []byte(`"secret"`)) {
		t.Fatal("listing must not include secrets")
	}
	// Dashboard roles.
	h.user(f, "viewer@scopes.example", auth.RoleViewer, "viewer-password-123")
	tok := h.do("POST", "/v1/auth/login", "", map[string]any{"email": "viewer@scopes.example", "password": "viewer-password-123"}).json(t)["token"].(string)
	if r := h.do("POST", "/v1/exports", tok, map[string]any{"stream": "s"}, "Delil-Project", f.ProjectID); r.Status != 403 {
		t.Fatalf("viewer export: %d", r.Status)
	}
	if r := h.do("POST", "/v1/events", tok, event("s", 3), "Delil-Project", f.ProjectID); r.Status != 403 {
		t.Fatalf("dashboard users never write events: %d", r.Status)
	}
	if r := h.do("GET", "/v1/overview", tok, nil, "Delil-Project", f.ProjectID); r.Status != 200 {
		t.Fatalf("viewer overview: %d %s", r.Status, r.Body)
	}
}

func TestCredentialsAndErrors(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("errors")
	cases := []struct {
		name   string
		resp   response
		status int
		code   string
	}{
		{"no token", h.do("GET", "/v1/events", "", nil), 401, "unauthorized"},
		{"malformed key", h.do("GET", "/v1/events", "dlk_nope", nil), 401, "unauthorized"},
		{"unknown key", h.do("GET", "/v1/events", strings.Replace(f.Key, f.Key[len(f.Key)-4:], "aaaa", 1), nil), 401, "unauthorized"},
		{"wrong media type", h.do("POST", "/v1/events", f.Key, "x=1", "Content-Type", "text/plain"), 415, "unsupported_media_type"},
		{"invalid json", h.do("POST", "/v1/events", f.Key, `{"stream":`), 422, "invalid_event"},
		{"unknown route", h.do("GET", "/v1/nothing", f.Key, nil), 404, "not_found"},
		{"bad cursor", h.do("GET", "/v1/events?cursor=bm90IGEgY3Vyc29y", f.Key, nil), 400, "invalid_request"},
		{"too large", h.do("POST", "/v1/events", f.Key, `{"stream":"s","data":"`+strings.Repeat("x", 300*1024)+`"}`), 413, "request_too_large"},
	}
	for _, c := range cases {
		if c.resp.Status != c.status || c.resp.code(t) != c.code {
			t.Errorf("%s: got %d %s, want %d %s", c.name, c.resp.Status, c.resp.code(t), c.status, c.code)
		}
		if c.resp.json(t)["error"].(map[string]any)["requestId"] == "" {
			t.Errorf("%s: errors must carry the request id", c.name)
		}
	}
	// Revoked and expired keys stop working immediately.
	victim := h.apiKey(f, auth.ScopeEventsRead)
	keys := h.do("GET", "/v1/api-keys", f.Key, nil).json(t)["data"].([]any)
	var victimID string
	for _, k := range keys {
		if strings.HasPrefix(victim, k.(map[string]any)["prefix"].(string)) {
			victimID = k.(map[string]any)["id"].(string)
		}
	}
	if r := h.do("DELETE", "/v1/api-keys/"+victimID, f.Key, nil); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Body)
	}
	if r := h.do("GET", "/v1/events", victim, nil); r.Status != 401 {
		t.Fatalf("revoked key still works: %d", r.Status)
	}
	// Security headers.
	r := h.do("GET", "/v1/events", f.Key, nil)
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store"} {
		if r.Header.Get(k) != v {
			t.Errorf("header %s = %q, want %q", k, r.Header.Get(k), v)
		}
	}
	if r.Header.Get("X-Request-Id") == "" {
		t.Error("responses must carry X-Request-Id")
	}
}

func TestIdempotencyOverHTTP(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("idem")
	first := h.do("POST", "/v1/events", f.Key, event("payments", 1), "Idempotency-Key", "webhook-evt-42")
	second := h.do("POST", "/v1/events", f.Key, event("payments", 1), "Idempotency-Key", "webhook-evt-42")
	if first.Status != 201 || second.Status != 201 || second.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %d %q", first.Status, second.Status, second.Header.Get("Idempotent-Replayed"))
	}
	if first.json(t)["id"] != second.json(t)["id"] {
		t.Fatal("replay must return the original event")
	}
	if r := h.do("POST", "/v1/events", f.Key, event("payments", 2), "Idempotency-Key", "webhook-evt-42"); r.Status != 422 || r.code(t) != "idempotency_key_reused" {
		t.Fatalf("mismatch: %d %s", r.Status, r.Body)
	}
	if r := h.do("POST", "/v1/events", f.Key, event("payments", 2), "Idempotency-Key", "bad key with spaces"); r.Status != 400 {
		t.Fatalf("invalid key: %d", r.Status)
	}
	stream := h.do("GET", "/v1/streams/payments", f.Key, nil).json(t)
	if stream["headSequence"].(float64) != 1 {
		t.Fatalf("exactly one event must exist, head=%v", stream["headSequence"])
	}
}

func TestBatchIngestion(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("batch")
	var events []any
	for i := 0; i < 10; i++ {
		events = append(events, event([]string{"a", "b"}[i%2], i))
	}
	r := h.do("POST", "/v1/events/batch", f.Key, map[string]any{"events": events})
	if r.Status != 201 || len(r.json(t)["data"].([]any)) != 10 {
		t.Fatalf("batch: %d %s", r.Status, r.Body)
	}
	bad := append(events, map[string]any{"stream": "a"})
	r = h.do("POST", "/v1/events/batch", f.Key, map[string]any{"events": bad})
	if r.Status != 422 || !strings.Contains(string(r.Body), "events[10].actor") {
		t.Fatalf("invalid batch: %d %s", r.Status, r.Body)
	}
	if h.do("GET", "/v1/streams/a", f.Key, nil).json(t)["headSequence"].(float64) != 5 {
		t.Fatal("a rejected batch must not write anything")
	}
}

func TestListFiltersAndPagination(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("pages")
	h.record(f, "contracts", 25)
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		r := h.do("GET", "/v1/events?limit=10&cursor="+cursor, f.Key, nil).json(t)
		for _, e := range r["data"].([]any) {
			seen[e.(map[string]any)["id"].(string)] = true
		}
		pages++
		if r["hasMore"] != true {
			break
		}
		cursor = r["nextCursor"].(string)
	}
	if len(seen) != 25 || pages != 3 {
		t.Fatalf("pagination: %d events over %d pages", len(seen), pages)
	}
	if n := len(h.do("GET", "/v1/events?actorId=user_1", f.Key, nil).json(t)["data"].([]any)); n != 8 {
		t.Fatalf("actor filter: %d", n)
	}
	if n := len(h.do("GET", "/v1/events?action=contract.*", f.Key, nil).json(t)["data"].([]any)); n != 25 {
		t.Fatalf("action prefix filter: %d", n)
	}
	if n := len(h.do("GET", "/v1/events?action=contract%25", f.Key, nil).json(t)["data"].([]any)); n != 0 {
		t.Fatalf("LIKE wildcards must be escaped: %d", n)
	}
	h.do("POST", "/v1/streams/contracts/verify", f.Key, nil)
	h.record(f, "contracts", 2)
	if n := len(h.do("GET", "/v1/events?verificationStatus=unverified", f.Key, nil).json(t)["data"].([]any)); n != 2 {
		t.Fatalf("unverified filter: %d", n)
	}
	if n := len(h.do("GET", "/v1/events?verificationStatus=verified&limit=100", f.Key, nil).json(t)["data"].([]any)); n != 25 {
		t.Fatalf("verified filter: %d", n)
	}
}

// The CLI's independent verification path: download raw chain records and
// public keys over HTTP and verify with pkg/verify on the client.
func TestClientSideVerificationOverChainEndpoint(t *testing.T) {
	h := newHarness(t)
	f := h.tenant("client")
	h.record(f, "cases", 23)
	keysResp := h.do("GET", "/v1/signing-keys/export", f.Key, nil)
	var keysFile struct {
		Keys []integrity.PublicKey `json:"keys"`
	}
	if err := json.Unmarshal(keysResp.Body, &keysFile); err != nil {
		t.Fatal(err)
	}
	keySet, err := integrity.NewKeySet(keysFile.Keys...)
	if err != nil {
		t.Fatal(err)
	}
	var items []verify.Item
	after := int64(0)
	var head struct {
		Sequence int64  `json:"sequence"`
		Hash     string `json:"hash"`
	}
	for {
		var page struct {
			Records           []integrity.Record `json:"records"`
			HasMore           bool               `json:"hasMore"`
			NextAfterSequence int64              `json:"nextAfterSequence"`
			Head              *struct {
				Sequence int64  `json:"sequence"`
				Hash     string `json:"hash"`
			} `json:"head"`
		}
		r := h.do("GET", fmt.Sprintf("/v1/streams/cases/chain?limit=7&afterSequence=%d", after), f.Key, nil)
		if err := json.Unmarshal(r.Body, &page); err != nil {
			t.Fatal(err)
		}
		head = *page.Head
		for _, rec := range page.Records {
			items = append(items, verify.Item{Record: rec})
		}
		if !page.HasMore {
			break
		}
		after = page.NextAfterSequence
	}
	hh, _ := integrity.ParseHash(head.Hash)
	rep, err := verify.VerifyStream(context.Background(), &verify.SliceSource{Items: items}, verify.StreamOptions{
		TenantID: f.TenantID, ProjectID: f.ProjectID, Stream: "cases", Keys: keySet, RequireContent: true,
		Head: &verify.Head{Sequence: head.Sequence, Hash: hh}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid || rep.EventsChecked != 23 || rep.PayloadsChecked != 23 {
		t.Fatalf("client-side verification: %v", rep.Failures)
	}
}

func TestSessionsAndLoginRateLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.LoginRateLimit = 5 })
	f := h.tenant("sessions")
	h.user(f, "ada@sessions.example", auth.RoleAdmin, "ada-password-12345")
	login := h.do("POST", "/v1/auth/login", "", map[string]any{"email": "ADA@sessions.example", "password": "ada-password-12345"})
	if login.Status != 200 {
		t.Fatalf("login: %d %s", login.Status, login.Body)
	}
	tok := login.json(t)["token"].(string)
	if r := h.do("GET", "/v1/auth/session", tok, nil); r.Status != 200 {
		t.Fatalf("session: %d", r.Status)
	}
	if r := h.do("GET", "/v1/overview", tok, nil); r.Status != 400 {
		t.Fatalf("missing Delil-Project must be rejected: %d", r.Status)
	}
	if r := h.do("POST", "/v1/projects", tok, map[string]any{"name": "Second Project"}); r.Status != 201 {
		t.Fatalf("admin creates project: %d %s", r.Status, r.Body)
	}
	if r := h.do("POST", "/v1/auth/logout", tok, nil); r.Status != 204 {
		t.Fatalf("logout: %d", r.Status)
	}
	if r := h.do("GET", "/v1/auth/session", tok, nil); r.Status != 401 {
		t.Fatalf("token must be invalid after logout: %d", r.Status)
	}
	// Unknown users and wrong passwords look the same; repeated attempts are limited.
	unknown := h.do("POST", "/v1/auth/login", "", map[string]any{"email": "nobody@sessions.example", "password": "whatever-123456"})
	wrong := h.do("POST", "/v1/auth/login", "", map[string]any{"email": "ada@sessions.example", "password": "wrong-password-1"})
	if unknown.Status != 401 || wrong.Status != 401 || unknown.json(t)["error"].(map[string]any)["message"] != wrong.json(t)["error"].(map[string]any)["message"] {
		t.Fatal("login failures must not reveal whether the account exists")
	}
	var limited response
	for i := 0; i < 6; i++ {
		limited = h.do("POST", "/v1/auth/login", "", map[string]any{"email": "ada@sessions.example", "password": "wrong-password-1"})
	}
	if limited.Status != 429 || limited.Header.Get("Retry-After") == "" {
		t.Fatalf("login rate limit: %d", limited.Status)
	}
}

func TestCORS(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.CORSOrigins = []string{"https://app.example"} })
	f := h.tenant("cors")
	r := h.do("GET", "/v1/events", f.Key, nil, "Origin", "https://evil.example")
	if r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unknown origins must not be allowed")
	}
	r = h.do("GET", "/v1/events", f.Key, nil, "Origin", "https://app.example")
	if r.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatal("allowed origin missing")
	}
	r = h.do("OPTIONS", "/v1/events", "", nil, "Origin", "https://app.example", "Access-Control-Request-Method", "POST")
	if r.Status != 204 || !strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "Idempotency-Key") {
		t.Fatalf("preflight: %d %v", r.Status, r.Header)
	}
}

func TestHealthReadyAndOpenAPI(t *testing.T) {
	h := newHarness(t)
	if r := h.do("GET", "/health", "", nil); r.Status != 200 {
		t.Fatal("health")
	}
	if r := h.do("GET", "/ready", "", nil); r.Status != 200 {
		t.Fatalf("ready: %s", r.Body)
	}
	if r := h.do("GET", "/openapi.yaml", "", nil); r.Status != 200 || !bytes.HasPrefix(r.Body, []byte("openapi:")) {
		t.Fatal("openapi")
	}
	if r := h.do("GET", "/metrics", "", nil); r.Status != 200 || !bytes.Contains(r.Body, []byte("delil_api_requests_total")) {
		t.Fatal("metrics")
	}
}
