// Package testutil builds a complete DƏLİL environment on a throwaway database
// for integration tests.
package testutil

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testdb"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/pkg/jcs"
)

// Env is a migrated database with the core services wired up.
type Env struct {
	DB       *testdb.Database
	Store    *store.Store
	Provider keys.Provider
	Keys     *keys.Manager
	Appender *audit.Appender
	Verifier *verification.Service
}

// NewEnv creates an environment using the local key provider with a random
// master key.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	d := testdb.New(t)
	st := store.New(d.Pool)
	master := make([]byte, keys.MasterKeySize)
	_, _ = rand.Read(master)
	provider, err := keys.NewLocalProvider(master)
	if err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st, provider)
	return &Env{
		DB:       d,
		Store:    st,
		Provider: provider,
		Keys:     km,
		Appender: audit.NewAppender(st, km, audit.AppenderOptions{}),
		Verifier: verification.NewService(st, km, "test"),
	}
}

// Project is a tenant with one project.
type Project struct {
	Tenant  store.Tenant
	Project store.Project
}

// CreateProject creates a tenant, a project and its initial signing key.
func (e *Env) CreateProject(t testing.TB, slug string) Project {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	p := Project{
		Tenant:  store.Tenant{ID: id.New(id.Tenant), Slug: slug, Name: strings.ToUpper(slug[:1]) + slug[1:], CreatedAt: now},
		Project: store.Project{ID: id.New(id.Project), Slug: "main", Name: "Main", CreatedAt: now},
	}
	p.Project.TenantID = p.Tenant.ID
	err := e.Store.InTx(ctx, func(tx pgx.Tx) error {
		if err := e.Store.CreateTenant(ctx, tx, p.Tenant); err != nil {
			return err
		}
		if err := e.Store.CreateProject(ctx, tx, p.Project); err != nil {
			return err
		}
		_, err := e.Keys.CreateInitialKey(ctx, tx, p.Tenant.ID, p.Project.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// EventJSON returns a valid single-event request body.
func EventJSON(stream string, i int) string {
	return fmt.Sprintf(`{"stream":%q,"actor":{"type":"user","id":"user_%d","displayName":"User %d"},
		"action":"contract.updated","resource":{"type":"contract","id":"contract_%d"},
		"before":{"status":"draft","version":%d},"after":{"status":"review","version":%d},
		"metadata":{"requestId":"req_%d"},"context":{"sourceIp":"203.0.113.%d"}}`,
		stream, i%7, i%7, i%13, i, i+1, i, i%250+1)
}

// Prepare decodes and prepares a request body with default settings.
func Prepare(t testing.TB, body string) audit.Prepared {
	t.Helper()
	tree, _, err := audit.ParseRequestBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	in, err := audit.DecodeEvent(tree)
	if err != nil {
		t.Fatal(err)
	}
	p, err := audit.Prepare(in, audit.DefaultSettings(), 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Append appends n events to stream one request at a time.
func (e *Env) Append(t testing.TB, p Project, stream string, n int) []audit.Committed {
	t.Helper()
	var out []audit.Committed
	for i := 0; i < n; i++ {
		res, err := e.Appender.Append(context.Background(), audit.AppendRequest{
			TenantID: p.Tenant.ID, ProjectID: p.Project.ID, Events: []audit.Prepared{Prepare(t, EventJSON(stream, i))},
		})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, res.Events...)
	}
	return out
}

// MustCanonical canonicalizes a JSON literal.
func MustCanonical(t testing.TB, s string) []byte {
	t.Helper()
	out, err := jcs.Canonicalize([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
