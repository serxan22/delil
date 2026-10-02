package audit_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testutil"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

func verifyStream(t *testing.T, env *testutil.Env, p testutil.Project, stream string) *verify.Report {
	t.Helper()
	rep, _, err := env.Verifier.VerifyStream(context.Background(), p.Tenant.ID, p.Project.ID, stream, verification.StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func requireValid(t *testing.T, rep *verify.Report, events int64) {
	t.Helper()
	if !rep.Valid {
		t.Fatalf("verification failed: %v", rep.Failures)
	}
	if rep.EventsChecked != events {
		t.Fatalf("expected %d events, verified %d", events, rep.EventsChecked)
	}
	if rep.Checks.StreamHead != verify.StatusValid {
		t.Fatalf("stream head check: %s", rep.Checks.StreamHead)
	}
}

func TestAppendBuildsVerifiableChains(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "legalflow")
	committed := env.Append(t, p, "contracts", 25)
	env.Append(t, p, "payments", 5)

	if committed[0].Record.Sequence != 1 || !committed[0].Record.PreviousHash.IsZero() {
		t.Fatal("the first event must be sequence 1 linked to the zero hash")
	}
	for i := 1; i < len(committed); i++ {
		if committed[i].Record.Sequence != int64(i+1) || committed[i].Record.PreviousHash != committed[i-1].Record.EventHash {
			t.Fatalf("event %d is not linked to its predecessor", i+1)
		}
	}
	requireValid(t, verifyStream(t, env, p, "contracts"), 25)
	requireValid(t, verifyStream(t, env, p, "payments"), 5)

	// Single-event verification sees the same chain.
	rep, _, err := env.Verifier.VerifyEvent(context.Background(), p.Tenant.ID, p.Project.ID, committed[10].Record.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid {
		t.Fatalf("event verification failed: %v", rep.Failures)
	}
}

func TestConcurrentAppendsToOneStream(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "concurrent")
	const workers, perWorker = 24, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_, err := env.Appender.Append(context.Background(), audit.AppendRequest{
					TenantID: p.Tenant.ID, ProjectID: p.Project.ID,
					Events: []audit.Prepared{testutil.Prepare(t, testutil.EventJSON("contracts", w*1000+i))},
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	st, err := env.Store.GetStream(context.Background(), p.Tenant.ID, p.Project.ID, "contracts")
	if err != nil {
		t.Fatal(err)
	}
	if st.HeadSequence != workers*perWorker {
		t.Fatalf("head sequence %d, want %d", st.HeadSequence, workers*perWorker)
	}
	requireValid(t, verifyStream(t, env, p, "contracts"), workers*perWorker)
}

func TestConcurrentBatchesAcrossStreams(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "batches")
	streams := []string{"contracts", "permissions", "payments", "cases"}
	const workers, batches = 12, 10
	var wg sync.WaitGroup
	var failures atomic.Int32
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for b := 0; b < batches; b++ {
				// Each batch touches the streams in a different order; the
				// appender locks them sorted, so this cannot deadlock.
				var events []audit.Prepared
				for i := 0; i < 4; i++ {
					s := streams[(w+b+i)%len(streams)]
					events = append(events, testutil.Prepare(t, testutil.EventJSON(s, w*100+b*10+i)))
				}
				if _, err := env.Appender.Append(context.Background(), audit.AppendRequest{
					TenantID: p.Tenant.ID, ProjectID: p.Project.ID, Events: events,
				}); err != nil {
					t.Error(err)
					failures.Add(1)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.FailNow()
	}
	var total int64
	for _, s := range streams {
		rep := verifyStream(t, env, p, s)
		if !rep.Valid {
			t.Fatalf("%s: %v", s, rep.Failures)
		}
		total += rep.EventsChecked
	}
	if total != workers*batches*4 {
		t.Fatalf("expected %d events in total, found %d", workers*batches*4, total)
	}
}

// failingProvider hands out signers that fail after a number of signatures.
type failingProvider struct {
	keys.Provider
	after int32
}

type failingSigner struct {
	integrity.Signer
	remaining *atomic.Int32
}

func (f failingSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if f.remaining.Add(-1) < 0 {
		return nil, errors.New("simulated KMS outage")
	}
	return f.Signer.Sign(ctx, msg)
}

func (p *failingProvider) Signer(ctx context.Context, k store.SigningKey) (integrity.Signer, error) {
	s, err := p.Provider.Signer(ctx, k)
	if err != nil {
		return nil, err
	}
	var remaining atomic.Int32
	remaining.Store(p.after)
	return failingSigner{Signer: s, remaining: &remaining}, nil
}

func TestBatchIsAtomic(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "atomic")
	env.Append(t, p, "contracts", 3)

	// Same key material, but the signer fails on the third signature.
	failing := &failingProvider{Provider: env.Provider, after: 2}
	km := keys.NewManager(env.Store, failing)
	appender := audit.NewAppender(env.Store, km, audit.AppenderOptions{})

	var events []audit.Prepared
	for i := 0; i < 5; i++ {
		s := []string{"contracts", "payments"}[i%2]
		events = append(events, testutil.Prepare(t, testutil.EventJSON(s, 100+i)))
	}
	_, err := appender.Append(context.Background(), audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID, Events: events})
	if err == nil {
		t.Fatal("expected the batch to fail")
	}
	st, _ := env.Store.GetStream(context.Background(), p.Tenant.ID, p.Project.ID, "contracts")
	if st.HeadSequence != 3 {
		t.Fatalf("a failed batch must not move the head (got %d)", st.HeadSequence)
	}
	if _, err := env.Store.GetStream(context.Background(), p.Tenant.ID, p.Project.ID, "payments"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stream created inside a failed batch must not exist: %v", err)
	}
	requireValid(t, verifyStream(t, env, p, "contracts"), 3)

	// Validation-level failure: stream limit.
	limited := audit.NewAppender(env.Store, env.Keys, audit.AppenderOptions{MaxStreamsPerProject: 1})
	_, err = limited.Append(context.Background(), audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID,
		Events: []audit.Prepared{testutil.Prepare(t, testutil.EventJSON("contracts", 1)), testutil.Prepare(t, testutil.EventJSON("cases", 2))}})
	if !errors.Is(err, audit.ErrTooManyStreams) {
		t.Fatalf("expected stream limit error, got %v", err)
	}
	requireValid(t, verifyStream(t, env, p, "contracts"), 3)
}

func TestIdempotency(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "idem")
	body := testutil.EventJSON("payments", 1)
	tree, hash, err := audit.ParseRequestBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	in, _ := audit.DecodeEvent(tree)
	prepared, _ := audit.Prepare(in, audit.DefaultSettings(), 1<<18)
	req := audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID, Events: []audit.Prepared{prepared},
		IdempotencyKey: "refund-9182", RequestHash: hash, Endpoint: "POST /v1/events"}

	first, err := env.Appender.Append(context.Background(), req)
	if err != nil || first.Replayed {
		t.Fatalf("first request: %v replayed=%v", err, first.Replayed)
	}
	second, err := env.Appender.Append(context.Background(), req)
	if err != nil || !second.Replayed {
		t.Fatalf("retry: %v replayed=%v", err, second.Replayed)
	}
	if second.Events[0].Record.EventID != first.Events[0].Record.EventID ||
		second.Events[0].Record.EventHash != first.Events[0].Record.EventHash {
		t.Fatal("a retry must return the original event")
	}

	other := req
	_, otherHash, _ := audit.ParseRequestBody([]byte(testutil.EventJSON("payments", 2)))
	other.RequestHash = otherHash
	if _, err := env.Appender.Append(context.Background(), other); !errors.Is(err, audit.ErrIdempotencyMismatch) {
		t.Fatalf("reusing a key for a different request must fail, got %v", err)
	}

	// Many concurrent requests with one key commit exactly one event.
	req.IdempotencyKey = "concurrent-key"
	var wg sync.WaitGroup
	ids := make([]string, 16)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := env.Appender.Append(context.Background(), req)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = res.Events[0].Record.EventID
		}(i)
	}
	wg.Wait()
	for _, v := range ids {
		if v != ids[0] {
			t.Fatalf("concurrent idempotent requests returned different events: %v", ids)
		}
	}
	requireValid(t, verifyStream(t, env, p, "payments"), 2)
}

func TestRecordedAtNeverDecreases(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "clock")
	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	offsets := []time.Duration{0, time.Second, -time.Hour, 2 * time.Second, -time.Minute}
	var i atomic.Int32
	skewed := audit.NewAppender(env.Store, env.Keys, audit.AppenderOptions{Now: func() time.Time {
		return base.Add(offsets[int(i.Load())%len(offsets)])
	}})
	var last time.Time
	for n := 0; n < len(offsets); n++ {
		i.Store(int32(n))
		res, err := skewed.Append(context.Background(), audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID,
			Events: []audit.Prepared{testutil.Prepare(t, testutil.EventJSON("cases", n))}})
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := integrity.ParseTime(res.Events[0].Record.RecordedAt)
		if ts.Before(last) {
			t.Fatalf("recordedAt went backwards: %s after %s", ts, last)
		}
		last = ts
	}
	requireValid(t, verifyStream(t, env, p, "cases"), int64(len(offsets)))
}

func TestKeyRotationDuringIngestion(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "rotation")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var appended atomic.Int64
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ctx.Err() == nil && i < 60; i++ {
				_, err := env.Appender.Append(context.Background(), audit.AppendRequest{TenantID: p.Tenant.ID, ProjectID: p.Project.ID,
					Events: []audit.Prepared{testutil.Prepare(t, testutil.EventJSON(fmt.Sprintf("s%d", w%3), i))}})
				if err != nil {
					t.Error(err)
					return
				}
				appended.Add(1)
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		time.Sleep(15 * time.Millisecond)
		if _, err := env.Keys.Rotate(context.Background(), p.Tenant.ID, p.Project.ID); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	cancel()
	keysList, err := env.Store.ListSigningKeys(context.Background(), p.Tenant.ID, p.Project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keysList) != 5 {
		t.Fatalf("expected 5 keys after 4 rotations, got %d", len(keysList))
	}
	var total int64
	for _, s := range []string{"s0", "s1", "s2"} {
		rep := verifyStream(t, env, p, s)
		if !rep.Valid {
			t.Fatalf("%s: %v", s, rep.Failures)
		}
		if len(rep.Warnings) != 0 {
			t.Fatalf("%s: rotation must not produce key-window warnings: %v", s, rep.Warnings)
		}
		total += rep.EventsChecked
	}
	if total != appended.Load() {
		t.Fatalf("verified %d events, appended %d", total, appended.Load())
	}
}

func TestRevokedKeyIsReplaced(t *testing.T) {
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "revoke")
	env.Append(t, p, "permissions", 3)
	active, err := env.Store.GetActiveSigningKey(context.Background(), p.Tenant.ID, p.Project.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := env.Keys.Revoke(context.Background(), p.Tenant.ID, p.Project.ID, active.ID, "laptop stolen")
	if err != nil || replacement == nil {
		t.Fatalf("revoking the active key must create a replacement: %v", err)
	}
	env.Append(t, p, "permissions", 2)
	rep := verifyStream(t, env, p, "permissions")
	// Events signed before the revocation still verify.
	requireValid(t, rep, 5)
	if len(rep.KeysUsed) != 2 {
		t.Fatalf("keys used: %v", rep.KeysUsed)
	}
	if _, err := env.Keys.Signer(context.Background(), active.ID); err == nil {
		t.Fatal("a revoked key must never sign again")
	}
}
