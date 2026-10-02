package export_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/serxan22/delil/internal/checkpoint"
	"github.com/serxan22/delil/internal/export"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testutil"
	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/integrity"
)

func newService(t *testing.T, env *testutil.Env) *export.Service {
	t.Helper()
	svc, err := export.NewService(env.Store, env.Keys, env.Verifier, export.Options{Dir: t.TempDir(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func process(t *testing.T, svc *export.Service, env *testutil.Env, p testutil.Project, x store.Export) store.Export {
	t.Helper()
	for svc.ProcessNext(context.Background()) {
	}
	got, err := env.Store.GetExport(context.Background(), p.Tenant.ID, p.Project.ID, x.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func verifyExport(t *testing.T, svc *export.Service, env *testutil.Env, p testutil.Project, x store.Export) *evidence.Result {
	t.Helper()
	f, _, err := svc.Open(context.Background(), p.Tenant.ID, p.Project.ID, x.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	keys, err := env.Store.PublicKeys(context.Background(), p.Tenant.ID, p.Project.ID)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := integrity.NewKeySet(keys...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := evidence.Verify(f, info.Size(), evidence.Options{TrustedKeys: trusted})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestExportRoundTrip(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "exporter")
	env.Append(t, p, "contracts", 40)
	st, _ := env.Store.GetStream(context.Background(), p.Tenant.ID, p.Project.ID, "contracts")
	cps := checkpoint.NewService(env.Store, env.Keys, nil)
	if _, _, err := cps.CreateForStream(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Keys.Rotate(context.Background(), p.Tenant.ID, p.Project.ID); err != nil {
		t.Fatal(err)
	}
	env.Append(t, p, "contracts", 20)
	svc := newService(t, env)

	// Whole stream, anchored at genesis, across a key rotation.
	x, err := svc.Create(context.Background(), p.Tenant.ID, p.Project.ID, export.Params{Stream: "contracts"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	x = process(t, svc, env, p, x)
	if x.Status != "completed" || *x.DisclosedEvents != 60 || *x.ChainEvents != 60 || !*x.VerificationValid {
		t.Fatalf("export: %+v (error %q)", x, x.Error)
	}
	res := verifyExport(t, svc, env, p, x)
	if !res.Valid || res.EventsChecked != 60 || len(res.KeysUsed) != 2 {
		t.Fatalf("whole-stream package: %v keys=%v", res.Failures, res.KeysUsed)
	}

	// A range after the checkpoint is anchored at it, and filters disclose a subset.
	from, to := int64(45), int64(55)
	x, err = svc.Create(context.Background(), p.Tenant.ID, p.Project.ID,
		export.Params{Stream: "contracts", FromSequence: &from, ToSequence: &to, ActorID: "user_3"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	x = process(t, svc, env, p, x)
	if x.Status != "completed" {
		t.Fatalf("filtered export failed: %s", x.Error)
	}
	res = verifyExport(t, svc, env, p, x)
	if !res.Valid || res.Package.ChainAnchor != evidence.AnchorCheckpoint || res.FirstSequence != 41 || res.LastSequence != 55 {
		t.Fatalf("anchored package: %v %+v", res.Failures, res.Package)
	}
	if res.PayloadsChecked == 0 || res.PayloadsChecked >= 11 {
		t.Fatalf("filter should disclose a subset, disclosed %d", res.PayloadsChecked)
	}

	// Time window selection.
	all, _ := env.Store.ChainPage(context.Background(), p.Tenant.ID, p.Project.ID, st.ID, 0, 100)
	fromT, toT := all[9].RecordedAt, all[19].RecordedAt
	x, err = svc.Create(context.Background(), p.Tenant.ID, p.Project.ID, export.Params{Stream: "contracts", From: &fromT, To: &toT}, "test")
	if err != nil {
		t.Fatal(err)
	}
	x = process(t, svc, env, p, x)
	if x.Status != "completed" || *x.FirstSequence != 10 {
		t.Fatalf("time-window export: %+v %s", x, x.Error)
	}
	if res := verifyExport(t, svc, env, p, x); !res.Valid {
		t.Fatalf("time-window package: %v", res.Failures)
	}
}

func TestExportValidationAndEmptySelection(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "exporter")
	env.Append(t, p, "contracts", 3)
	svc := newService(t, env)
	now := time.Now()
	earlier := now.Add(-time.Hour)
	bad := []export.Params{
		{},
		{Stream: "contracts", From: &now, To: &earlier},
	}
	for _, p2 := range bad {
		if _, err := svc.Create(context.Background(), p.Tenant.ID, p.Project.ID, p2, "test"); !errors.Is(err, export.ErrInvalidParams) {
			t.Errorf("params %+v: expected ErrInvalidParams, got %v", p2, err)
		}
	}
	if _, err := svc.Create(context.Background(), p.Tenant.ID, p.Project.ID, export.Params{Stream: "missing"}, "test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown stream: %v", err)
	}
	future := now.Add(24 * time.Hour)
	later := future.Add(time.Hour)
	x, err := svc.Create(context.Background(), p.Tenant.ID, p.Project.ID, export.Params{Stream: "contracts", From: &future, To: &later}, "test")
	if err != nil {
		t.Fatal(err)
	}
	x = process(t, svc, env, p, x)
	if x.Status != "failed" || x.Error == "" {
		t.Fatalf("an empty selection must fail clearly: %+v", x)
	}
	if _, _, err := svc.Open(context.Background(), p.Tenant.ID, p.Project.ID, x.ID); !errors.Is(err, export.ErrNotReady) {
		t.Fatalf("downloading a failed export: %v", err)
	}
	// Exports are tenant-scoped.
	other := env.CreateProject(t, "other")
	if _, _, err := svc.Open(context.Background(), other.Tenant.ID, other.Project.ID, x.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant export access must be not found, got %v", err)
	}
}
