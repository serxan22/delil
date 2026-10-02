package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/db"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testdb"
	"github.com/serxan22/delil/internal/testutil"
)

// The append-only guards must hold even for a role with full table
// privileges, as long as it does not disable triggers.
func TestAppendOnlyGuards(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "guards")
	env.Append(t, p, "contracts", 5)
	ctx := context.Background()
	pool := env.DB.Pool
	st, _ := env.Store.GetStream(ctx, p.Tenant.ID, p.Project.ID, "contracts")

	rejected := []struct {
		name  string
		sql   string
		check func(error) bool
	}{
		{"update event", `UPDATE audit_events SET action = 'x' WHERE stream_id = $1`, store.IsInsufficientPrivilege},
		{"delete event", `DELETE FROM audit_events WHERE stream_id = $1`, store.IsInsufficientPrivilege},
		{"move head back", `UPDATE audit_streams SET head_sequence = 2 WHERE id = $1`, store.IsCheckViolation},
		{"point head nowhere", `UPDATE audit_streams SET head_hash = sha256('x'::bytea) WHERE id = $1`, store.IsCheckViolation},
		{"rename stream", `UPDATE audit_streams SET name = 'renamed' WHERE id = $1`, store.IsCheckViolation},
		{"delete stream", `DELETE FROM audit_streams WHERE id = $1`, store.IsInsufficientPrivilege},
	}
	for _, tc := range rejected {
		_, err := pool.Exec(ctx, tc.sql, st.ID)
		if err == nil || !tc.check(err) {
			t.Errorf("%s: expected rejection, got %v", tc.name, err)
		}
	}
	for _, table := range []string{"audit_events", "checkpoints", "audit_streams", "signing_keys"} {
		if _, err := pool.Exec(ctx, "TRUNCATE "+table+" CASCADE"); err == nil || !store.IsInsufficientPrivilege(err) {
			t.Errorf("TRUNCATE %s: expected rejection, got %v", table, err)
		}
	}

	// Signing keys: material is immutable, status only moves forward.
	key, _ := env.Store.GetActiveSigningKey(ctx, p.Tenant.ID, p.Project.ID)
	for name, sql := range map[string]string{
		"replace public key": `UPDATE signing_keys SET public_key = sha256('x'::bytea) WHERE id = $1`,
		"delete key":         `DELETE FROM signing_keys WHERE id = $1`,
	} {
		if _, err := pool.Exec(ctx, sql, key.ID); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if _, err := env.Keys.Rotate(ctx, p.Tenant.ID, p.Project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET status = 'active', retired_at = NULL WHERE id = $1`, key.ID); err == nil {
		t.Error("a retired key must not be reactivated")
	}
}

// The linkage trigger rejects events that do not extend the chain, even when
// inserted directly with valid-looking data.
func TestLinkageTrigger(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "linkage")
	committed := env.Append(t, p, "contracts", 3)
	ctx := context.Background()
	last := committed[2]

	// Copy a real row and change only what each case needs, so that the
	// trigger (not some other constraint) is what rejects it.
	insert := func(seq int64, prev []byte) error {
		ev, err := env.Store.GetEvent(ctx, p.Tenant.ID, p.Project.ID, last.Record.EventID)
		if err != nil {
			t.Fatal(err)
		}
		ev.ID = id.New(id.Event)
		ev.Sequence = seq
		ev.PreviousHash = prev
		h := make([]byte, 32)
		_, _ = rand.Read(h)
		ev.EventHash = h
		return env.Store.InsertEvent(ctx, env.DB.Pool, ev)
	}
	if err := insert(5, last.Record.EventHash[:]); err == nil || !store.IsCheckViolation(err) {
		t.Errorf("a sequence gap must be rejected, got %v", err)
	}
	wrong := make([]byte, 32)
	if err := insert(4, wrong); err == nil || !store.IsCheckViolation(err) {
		t.Errorf("a wrong previous hash must be rejected, got %v", err)
	}
	if err := insert(3, committed[1].Record.EventHash[:]); err == nil || !store.IsUniqueViolation(err) {
		t.Errorf("a duplicate sequence must be rejected, got %v", err)
	}
}

// The default deployment runs the API as a role that cannot modify history at
// all: no UPDATE/DELETE privileges, no ownership to disable triggers.
func TestLeastPrivilegeRuntimeRole(t *testing.T) {
	env := testutil.NewEnv(t)
	ctx := context.Background()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	role := "delil_app_" + hex.EncodeToString(suffix)
	password := hex.EncodeToString(suffix) + "-test-only"

	exec := func(sql string) {
		if _, err := env.DB.Pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " LOGIN PASSWORD '" + password + "'")
	t.Cleanup(func() {
		_, _ = env.DB.Pool.Exec(context.Background(), "DROP OWNED BY "+pgx.Identifier{role}.Sanitize())
		_, _ = env.DB.Pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
	})
	if err := db.GrantRuntimePrivileges(ctx, env.DB.Pool, role); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantRuntimePrivileges(ctx, env.DB.Pool, role); err != nil {
		t.Fatalf("granting must be idempotent: %v", err)
	}
	if err := db.GrantRuntimePrivileges(ctx, env.DB.Pool, "bad role; drop table x"); err == nil {
		t.Fatal("role names must be validated")
	}

	u, _ := url.Parse(env.DB.URL)
	u.User = url.UserPassword(role, password)
	appPool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer appPool.Close()

	// The runtime role can do its job end to end...
	p := env.CreateProject(t, "leastpriv")
	appStore := store.New(appPool)
	km := keys.NewManager(appStore, env.Provider)
	app := audit.NewAppender(appStore, km, audit.AppenderOptions{})
	if _, err := app.Append(ctx, audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID,
		Events: []audit.Prepared{testutil.Prepare(t, testutil.EventJSON("contracts", 1))}}); err != nil {
		t.Fatalf("runtime role cannot append: %v", err)
	}
	if _, err := km.Rotate(ctx, p.Tenant.ID, p.Project.ID); err != nil {
		t.Fatalf("runtime role cannot rotate keys: %v", err)
	}

	// ...but cannot rewrite history, even by disabling triggers.
	for _, sql := range []string{
		`UPDATE audit_events SET action = 'x'`,
		`DELETE FROM audit_events`,
		`DELETE FROM checkpoints`,
		`ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`,
		`SET session_replication_role = replica`,
		`DROP TABLE audit_events`,
	} {
		_, err := appPool.Exec(ctx, sql)
		if err == nil {
			t.Errorf("runtime role was allowed to run %q", sql)
		}
	}
}

func TestMigrationsAreIdempotentAndChecksummed(t *testing.T) {
	d := testdb.New(t)
	ctx := context.Background()
	ran, err := db.Migrate(ctx, d.Pool)
	if err != nil || len(ran) != 0 {
		t.Fatalf("re-running migrations must be a no-op: ran=%d err=%v", len(ran), err)
	}
	ok, err := db.UpToDate(ctx, d.Pool)
	if err != nil || !ok {
		t.Fatalf("schema should be up to date: %v", err)
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE delil_schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx, d.Pool); !errors.Is(err, db.ErrMigrationModified) {
		t.Fatalf("a modified migration must be detected, got %v", err)
	}
	ok, _ = db.UpToDate(ctx, d.Pool)
	if ok {
		t.Fatal("status must report the modified migration")
	}
}
