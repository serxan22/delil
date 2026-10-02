package cli_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/app"
	"github.com/serxan22/delil/internal/bootstrap"
	"github.com/serxan22/delil/internal/cli"
	"github.com/serxan22/delil/internal/config"
	"github.com/serxan22/delil/internal/testdb"
)

func TestCLIEndToEnd(t *testing.T) {
	d := testdb.New(t)
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	cfg := &config.Config{Env: config.EnvDevelopment, KeyProvider: "local", MasterKey: mk, ExportDir: t.TempDir(),
		MaxEventBytes: 64 << 10, MaxBatchEvents: 50, MaxRequestBytes: 1 << 20, MaxStreamsPerProject: 10,
		RateLimitRPS: 1000, RateLimitBurst: 1000, SessionTTL: time.Hour, IdempotencyTTL: time.Hour, ExportTTL: time.Hour,
		CheckpointEvery: 1000}
	a, err := app.Build(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", d.Pool)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bootstrap.Run(context.Background(), a, bootstrap.Options{OrgName: "LegalFlow", ProjectName: "Main",
		AdminEmail: "admin@example.test", AdminPassword: "admin-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.API.Handler())
	defer srv.Close()
	exportsDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); <-exportsDone }()
	go func() { a.Exports.Run(ctx, 100*time.Millisecond); close(exportsDone) }()

	dir := t.TempDir()
	t.Setenv("DELIL_URL", srv.URL)
	t.Setenv("DELIL_API_KEY", res.APIKey)
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := cli.Run(context.Background(), append([]string{"--config", filepath.Join(dir, "cfg.json"), "--no-color"}, args...), &out, &errOut)
		return code, out.String() + errOut.String()
	}

	for i := 0; i < 12; i++ {
		req := httptest.NewRequest("POST", "/v1/events", strings.NewReader(
			`{"stream":"contracts","actor":{"type":"user","id":"u1"},"action":"contract.updated","after":{"n":`+string(rune('0'+i%10))+`}}`))
		req.Header.Set("Authorization", "Bearer "+res.APIKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.API.Handler().ServeHTTP(rec, req)
		if rec.Code != 201 {
			t.Fatalf("record: %d %s", rec.Code, rec.Body)
		}
	}

	if code, out := run("verify", "stream", "contracts"); code != cli.ExitOK || !strings.Contains(out, "Tampering detected: NO") {
		t.Fatalf("verify: %d\n%s", code, out)
	}
	if code, out := run("status"); code != 0 || !strings.Contains(out, "12 total") {
		t.Fatalf("status: %d\n%s", code, out)
	}
	if code, _ := run("verify", "--bogus-flag"); code != cli.ExitUsage {
		t.Fatalf("usage error exit code: %d", code)
	}
	keysFile := filepath.Join(dir, "trusted.json")
	if code, out := run("keys", "export", "-o", keysFile); code != 0 {
		t.Fatalf("keys export: %s", out)
	}
	pkg := filepath.Join(dir, "evidence.zip")
	if code, out := run("export", "--stream", "contracts", "-o", pkg); code != 0 || !strings.Contains(out, "Package integrity:  VALID") {
		t.Fatalf("export: %d\n%s", code, out)
	}
	if code, out := run("verify-export", pkg, "--trusted-keys", keysFile, "--json"); code != 0 || !strings.Contains(out, `"keysTrusted": true`) {
		t.Fatalf("verify-export: %d\n%s", code, out)
	}
	data, _ := os.ReadFile(pkg)
	corrupt := filepath.Join(dir, "corrupt.zip")
	data[len(data)/3] ^= 0xff // entries are compressed: flip a byte instead of editing text
	_ = os.WriteFile(corrupt, data, 0o600)
	if code, _ := run("verify-export", corrupt); code != cli.ExitFailed {
		t.Fatalf("a corrupted package must fail with exit 1, got %d", code)
	}

	// Tamper with the database: the CLI's independent verification fails.
	d.Tamper(t, func(ctx context.Context, conn *pgx.Conn) {
		testdb.Exec(t, ctx, conn, `UPDATE audit_events SET content = replace(content, '"u1"', '"u2"') WHERE sequence = 7`)
	})
	code, out := run("verify", "stream", "contracts")
	if code != cli.ExitFailed || !strings.Contains(out, "Verification FAILED") || !strings.Contains(out, "Sequence:  7") {
		t.Fatalf("tampering must be reported with exit 1: %d\n%s", code, out)
	}
	if code, _ := run("verify", "--stream", "contracts", "--json"); code != cli.ExitFailed {
		t.Fatalf("json mode exit code: %d", code)
	}
}
