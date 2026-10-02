// Package testdb provisions throwaway PostgreSQL databases for tests.
//
// Database tests run when DELIL_TEST_DATABASE_URL points at a server where the
// connecting role may create databases, for example
//
//	DELIL_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable
//
// Each call creates a fresh database, applies all migrations and drops the
// database when the test ends. Without the variable the tests are skipped
// (CI always sets it).
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serxan22/delil/internal/db"
)

// EnvVar names the admin connection string.
const EnvVar = "DELIL_TEST_DATABASE_URL"

// Database is a migrated test database.
type Database struct {
	Pool *pgxpool.Pool
	// URL connects as the admin role (superuser in development), which can
	// bypass the append-only guards; tamper tests use it on purpose.
	URL  string
	Name string
}

// New creates a fresh, migrated database.
func New(t testing.TB) *Database {
	t.Helper()
	adminURL := os.Getenv(EnvVar)
	if adminURL == "" {
		t.Skipf("set %s to run database tests", EnvVar)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("testdb: connect to %s: %v", EnvVar, err)
	}
	defer admin.Close(ctx)

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "delil_test_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("testdb: create database: %v", err)
	}

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("testdb: parse url: %v", err)
	}
	u.Path = "/" + name
	dbURL := u.String()

	pool, err := db.Connect(ctx, dbURL, db.Options{MaxConns: 40, ApplicationName: "delil-test"})
	if err != nil {
		t.Fatalf("testdb: connect: %v", err)
	}
	if _, err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("testdb: migrate: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, adminURL)
		if err != nil {
			t.Logf("testdb: cleanup connect: %v", err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("testdb: drop %s: %v", name, err)
		}
	})
	return &Database{Pool: pool, URL: dbURL, Name: name}
}

// Tamper runs fn on a dedicated connection with session_replication_role =
// replica, which disables the append-only triggers (and foreign keys). It
// simulates a malicious administrator; it requires superuser privileges.
func (d *Database) Tamper(t testing.TB, fn func(ctx context.Context, conn *pgx.Conn)) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, d.URL)
	if err != nil {
		t.Fatalf("testdb: tamper connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "SET session_replication_role = replica"); err != nil {
		t.Fatalf("testdb: disabling triggers requires a superuser: %v", err)
	}
	fn(ctx, conn)
}

// Exec runs a statement as the admin role, failing the test on error.
func Exec(t testing.TB, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("testdb: %s: %v", sql, err)
	}
}
