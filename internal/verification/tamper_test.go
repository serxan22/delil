package verification_test

// The database tamper suite. Every test builds a real chain through the
// production append path, then edits PostgreSQL directly as a malicious
// administrator would (triggers disabled via session_replication_role), and
// asserts that verification fails for the right reason at the right place.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/checkpoint"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/testdb"
	"github.com/serxan22/delil/internal/testutil"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

type fixture struct {
	env    *testutil.Env
	p      testutil.Project
	stream store.Stream
}

func newFixture(t *testing.T, events int) *fixture {
	t.Helper()
	env := testutil.NewEnv(t)
	p := env.CreateProject(t, "tamper")
	env.Append(t, p, "contracts", events)
	st, err := env.Store.GetStream(context.Background(), p.Tenant.ID, p.Project.ID, "contracts")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{env: env, p: p, stream: st}
	if rep := f.verify(t, verification.StreamOptions{}); !rep.Valid {
		t.Fatalf("untouched chain must verify: %v", rep.Failures)
	}
	return f
}

func (f *fixture) verify(t *testing.T, opts verification.StreamOptions) *verify.Report {
	t.Helper()
	rep, _, err := f.env.Verifier.VerifyStream(context.Background(), f.p.Tenant.ID, f.p.Project.ID, "contracts", opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func (f *fixture) tamper(t *testing.T, statements ...string) {
	t.Helper()
	f.env.DB.Tamper(t, func(ctx context.Context, conn *pgx.Conn) {
		for _, s := range statements {
			testdb.Exec(t, ctx, conn, s, f.stream.ID)
		}
	})
}

func expectFirst(t *testing.T, rep *verify.Report, code verify.Code, seq int64) {
	t.Helper()
	if rep.Valid {
		t.Fatalf("tampering with expected %s at %d went undetected", code, seq)
	}
	if rep.FirstFailure == nil || rep.FirstFailure.Code != code || rep.FirstFailure.Sequence != seq {
		t.Fatalf("expected first failure %s at sequence %d, got %+v\nall failures: %v", code, seq, rep.FirstFailure, rep.Failures)
	}
}

func contains(rep *verify.Report, code verify.Code, seq int64) bool {
	for _, f := range rep.Failures {
		if f.Code == code && f.Sequence == seq {
			return true
		}
	}
	return false
}

func TestTamperChangedPayloadInDatabase(t *testing.T) {
	f := newFixture(t, 100)
	f.tamper(t, `UPDATE audit_events SET content = replace(content, '"status":"review"', '"status":"approved"')
		WHERE stream_id = $1 AND sequence = 37`)
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodePayloadHashMismatch, 37)
	if rep.FailureCount != 1 {
		t.Fatalf("only event 37 was touched: %v", rep.Failures)
	}
}

func TestTamperChangedActorID(t *testing.T) {
	t.Run("index column", func(t *testing.T) {
		f := newFixture(t, 40)
		f.tamper(t, `UPDATE audit_events SET actor_id = 'user_innocent' WHERE stream_id = $1 AND sequence = 20`)
		expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeIndexedFieldMismatch, 20)
	})
	t.Run("signed content", func(t *testing.T) {
		f := newFixture(t, 40)
		// Event 20 was written by user_5 (see testutil.EventJSON).
		f.tamper(t, `UPDATE audit_events SET content = replace(content, '"id":"user_5"', '"id":"user_6"'),
			actor_id = 'user_6' WHERE stream_id = $1 AND sequence = 20`)
		expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodePayloadHashMismatch, 20)
	})
}

func TestTamperChangedTimestamp(t *testing.T) {
	f := newFixture(t, 50)
	f.tamper(t, `UPDATE audit_events SET recorded_at = recorded_at + interval '1 millisecond'
		WHERE stream_id = $1 AND sequence = 30`)
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeEventHashMismatch, 30)
}

func TestTamperDeletedEvent(t *testing.T) {
	f := newFixture(t, 100)
	f.tamper(t, `DELETE FROM audit_events WHERE stream_id = $1 AND sequence = 50`)
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodeSequenceGap, 51)
	if !contains(rep, verify.CodePreviousHashMismatch, 51) {
		t.Fatalf("the broken link must be reported too: %v", rep.Failures)
	}
}

func TestTamperSwappedEvents(t *testing.T) {
	f := newFixture(t, 100)
	f.tamper(t,
		`UPDATE audit_events SET sequence = 1000000 WHERE stream_id = $1 AND sequence = 80`,
		`UPDATE audit_events SET sequence = 80 WHERE stream_id = $1 AND sequence = 81`,
		`UPDATE audit_events SET sequence = 81 WHERE stream_id = $1 AND sequence = 1000000`)
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodePreviousHashMismatch, 80)
	for _, want := range []struct {
		code verify.Code
		seq  int64
	}{{verify.CodeEventHashMismatch, 80}, {verify.CodeEventHashMismatch, 81}, {verify.CodePreviousHashMismatch, 81}} {
		if !contains(rep, want.code, want.seq) {
			t.Errorf("missing %s at %d", want.code, want.seq)
		}
	}
}

func TestTamperChangedPreviousHash(t *testing.T) {
	f := newFixture(t, 80)
	f.tamper(t, `UPDATE audit_events SET previous_hash = sha256('forged'::bytea) WHERE stream_id = $1 AND sequence = 60`)
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodePreviousHashMismatch, 60)
	if !contains(rep, verify.CodeEventHashMismatch, 60) {
		t.Fatalf("previous_hash is covered by the event hash: %v", rep.Failures)
	}
}

func TestTamperForgedSignature(t *testing.T) {
	f := newFixture(t, 30)
	f.tamper(t, `UPDATE audit_events SET signature = decode(repeat('ab', 64), 'hex') WHERE stream_id = $1 AND sequence = 10`)
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodeSignatureInvalid, 10)
	if rep.FailureCount != 1 {
		t.Fatalf("only the signature is wrong: %v", rep.Failures)
	}
}

func TestTamperSequenceGap(t *testing.T) {
	f := newFixture(t, 100)
	f.tamper(t, `UPDATE audit_events SET sequence = 105 WHERE stream_id = $1 AND sequence = 100`,
		`UPDATE audit_streams SET head_sequence = 105 WHERE id = $1`)
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeSequenceGap, 105)
}

func TestTamperWrongPublicKey(t *testing.T) {
	f := newFixture(t, 20)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	f.env.DB.Tamper(t, func(ctx context.Context, conn *pgx.Conn) {
		testdb.Exec(t, ctx, conn, `UPDATE signing_keys SET public_key = $1 WHERE project_id = $2`, []byte(other), f.p.Project.ID)
	})
	rep := f.verify(t, verification.StreamOptions{})
	expectFirst(t, rep, verify.CodeUnknownSigningKey, 1)
	found := false
	for _, fl := range rep.Failures {
		found = found || fl.Code == verify.CodeSigningKeyInvalid
	}
	if !found {
		t.Fatalf("the inconsistent key record must be reported: %v", rep.Failures)
	}
}

func TestTamperInsertedForgedEvent(t *testing.T) {
	f := newFixture(t, 30)
	ctx := context.Background()
	last, err := f.env.Store.GetEventBySequence(ctx, f.p.Tenant.ID, f.p.Project.ID, f.stream.ID, 30)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	attacker, _ := integrity.NewEd25519Signer(priv)
	content := testutil.MustCanonical(t, `{"action":"refund.issued","actor":{"id":"user_1","type":"user"}}`)
	rec, err := integrity.Seal(ctx, integrity.SealInput{
		TenantID: f.p.Tenant.ID, ProjectID: f.p.Project.ID, Stream: "contracts", Sequence: 31,
		EventID: "evt_01JFORGEDFORGEDFORGEDFORGE", RecordedAt: last.RecordedAt,
		PreviousHash: integrity.Hash(last.EventHash), CanonicalContent: content,
	}, attacker)
	if err != nil {
		t.Fatal(err)
	}
	f.env.DB.Tamper(t, func(ctx context.Context, conn *pgx.Conn) {
		row := store.Event{ID: rec.EventID, TenantID: rec.TenantID, ProjectID: rec.ProjectID, StreamID: f.stream.ID,
			Sequence: 31, SchemaVersion: 1, ActorType: "user", ActorID: "user_1", Action: "refund.issued",
			RecordedAt: last.RecordedAt, Content: string(content), PayloadHash: rec.PayloadHash[:],
			PreviousHash: rec.PreviousHash[:], EventHash: rec.EventHash[:], SigningKeyID: rec.KeyID, Signature: rec.Signature}
		if err := f.env.Store.InsertEvent(ctx, conn, row); err != nil {
			t.Fatal(err)
		}
		testdb.Exec(t, ctx, conn, `UPDATE audit_streams SET head_sequence = 31, head_hash = $2 WHERE id = $1`,
			f.stream.ID, rec.EventHash[:])
	})
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeUnknownSigningKey, 31)
}

func TestTamperEventMovedToAnotherStream(t *testing.T) {
	f := newFixture(t, 20)
	f.env.Append(t, f.p, "payments", 5)
	payments, _ := f.env.Store.GetStream(context.Background(), f.p.Tenant.ID, f.p.Project.ID, "payments")
	f.env.DB.Tamper(t, func(ctx context.Context, conn *pgx.Conn) {
		testdb.Exec(t, ctx, conn, `UPDATE audit_events SET stream_id = $2, sequence = 6 WHERE stream_id = $1 AND sequence = 20`,
			f.stream.ID, payments.ID)
	})
	// The source stream is now shorter than its head says...
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeHeadMismatch, 20)
	// ...and the destination stream contains an event whose signed header names
	// another stream.
	rep, _, err := f.env.Verifier.VerifyStream(context.Background(), f.p.Tenant.ID, f.p.Project.ID, "payments", verification.StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	expectFirst(t, rep, verify.CodePreviousHashMismatch, 6)
	if !contains(rep, verify.CodeEventHashMismatch, 6) {
		t.Fatalf("the transplanted event must fail its hash: %v", rep.Failures)
	}
}

func TestTamperHeadPointer(t *testing.T) {
	f := newFixture(t, 100)
	f.tamper(t, `UPDATE audit_streams SET head_sequence = 99,
		head_hash = (SELECT event_hash FROM audit_events WHERE stream_id = $1 AND sequence = 99) WHERE id = $1`)
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeHeadMismatch, 100)
}

func TestTamperNonCanonicalEncoding(t *testing.T) {
	f := newFixture(t, 10)
	f.tamper(t, `UPDATE audit_events SET content = ' ' || content WHERE stream_id = $1 AND sequence = 4`)
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodePayloadNotCanonical, 4)
}

// Truncation that also rewinds the head is only visible through checkpoints;
// if the attacker deletes the stored checkpoints too, only a witness copy kept
// elsewhere reveals it.
func TestTamperTruncationAndRollback(t *testing.T) {
	f := newFixture(t, 100)
	cps := checkpoint.NewService(f.env.Store, f.env.Keys, nil)
	cp, created, err := cps.CreateForStream(context.Background(), f.stream)
	if err != nil || !created {
		t.Fatalf("checkpoint: %v", err)
	}
	witness := cp.Integrity()

	f.tamper(t,
		`DELETE FROM audit_events WHERE stream_id = $1 AND sequence > 90`,
		`UPDATE audit_streams SET head_sequence = 90,
			head_hash = (SELECT event_hash FROM audit_events WHERE stream_id = $1 AND sequence = 90) WHERE id = $1`)
	expectFirst(t, f.verify(t, verification.StreamOptions{}), verify.CodeCheckpointBeyondHead, 100)

	f.tamper(t, `DELETE FROM checkpoints WHERE stream_id = $1`)
	if rep := f.verify(t, verification.StreamOptions{}); !rep.Valid {
		t.Fatalf("without any surviving checkpoint the rollback is internally consistent: %v", rep.Failures)
	}
	rep := f.verify(t, verification.StreamOptions{Witnesses: []integrity.Checkpoint{witness}})
	expectFirst(t, rep, verify.CodeCheckpointBeyondHead, 100)
}
