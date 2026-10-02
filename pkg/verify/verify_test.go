package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
)

const (
	tenantID  = "org_01JDELILTENANT0000000000"
	projectID = "prj_01JDELILPROJECT000000000"
	stream    = "contracts"
)

var baseTime = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func newSigner(t testing.TB) *integrity.Ed25519Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := integrity.NewEd25519Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keySet(t testing.TB, signers ...integrity.Signer) *integrity.KeySet {
	t.Helper()
	var keys []integrity.PublicKey
	for _, s := range signers {
		keys = append(keys, integrity.NewPublicKey(s.PublicKey()))
	}
	ks, err := integrity.NewKeySet(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func content(t testing.TB, i int, actor string) []byte {
	t.Helper()
	raw := fmt.Sprintf(`{"action":"contract.updated","actor":{"type":"user","id":%q},`+
		`"resource":{"type":"contract","id":"contract_%d"},"before":{"version":%d},"after":{"version":%d},`+
		`"changes":[{"from":%d,"op":"replace","path":"/version","to":%d}]}`, actor, i%17, i, i+1, i, i+1)
	c, err := jcs.Canonicalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func eventID(i int) string { return fmt.Sprintf("evt_01JDELILEVENT%011d", i) }

// buildChain seals n events (sequences start..start+n-1) linked to prev.
func buildChain(t testing.TB, signer integrity.Signer, start int64, n int, prev integrity.Hash) []Item {
	t.Helper()
	items := make([]Item, 0, n)
	for i := 0; i < n; i++ {
		seq := start + int64(i)
		c := content(t, int(seq), fmt.Sprintf("user_%d", seq%5))
		rec, err := integrity.Seal(context.Background(), integrity.SealInput{
			TenantID: tenantID, ProjectID: projectID, Stream: stream,
			Sequence: seq, EventID: eventID(int(seq)),
			RecordedAt:   baseTime.Add(time.Duration(seq) * time.Second),
			PreviousHash: prev, CanonicalContent: c,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := integrity.ParseContent(rec.Content)
		idx := parsed.Index()
		items = append(items, Item{Record: rec, Index: &idx})
		prev = rec.EventHash
	}
	return items
}

func opts(keys *integrity.KeySet) StreamOptions {
	return StreamOptions{TenantID: tenantID, ProjectID: projectID, Stream: stream, Keys: keys,
		RequireContent: true, RequireCanonicalContent: true}
}

func run(t testing.TB, items []Item, o StreamOptions) *Report {
	t.Helper()
	rep, err := VerifyStream(context.Background(), &SliceSource{Items: items, BatchSize: 64}, o)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func headOf(items []Item) *Head {
	if len(items) == 0 {
		return &Head{}
	}
	last := items[len(items)-1].Record
	return &Head{Sequence: last.Sequence, Hash: last.EventHash}
}

func clone(items []Item) []Item {
	out := make([]Item, len(items))
	for i, it := range items {
		out[i] = it
		out[i].Record.Content = append([]byte(nil), it.Record.Content...)
		out[i].Record.Signature = append([]byte(nil), it.Record.Signature...)
		if it.Index != nil {
			idx := *it.Index
			out[i].Index = &idx
		}
	}
	return out
}

// rehash recomputes payload and event hashes the way an attacker without the
// signing key would, leaving the old signature in place.
func rehash(t testing.TB, it *Item) {
	t.Helper()
	c, err := jcs.Canonicalize(it.Record.Content)
	if err != nil {
		t.Fatal(err)
	}
	it.Record.PayloadHash = integrity.PayloadHash(c)
	h, err := it.Record.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	it.Record.EventHash = h
}

func expectValid(t *testing.T, rep *Report) {
	t.Helper()
	if !rep.Valid || rep.FailureCount != 0 || rep.TamperingDetected {
		t.Fatalf("expected a valid report, got %d failure(s): %v", rep.FailureCount, rep.Failures)
	}
}

// expectFailure asserts that the first failure is code at sequence seq.
func expectFailure(t *testing.T, rep *Report, code Code, seq int64) {
	t.Helper()
	if rep.Valid || !rep.TamperingDetected {
		t.Fatalf("expected verification to fail with %s at %d, but it passed", code, seq)
	}
	ff := rep.FirstFailure
	if ff == nil || ff.Code != code || ff.Sequence != seq {
		t.Fatalf("expected first failure %s at sequence %d, got %+v\nall: %v", code, seq, ff, rep.Failures)
	}
}

func hasFailure(rep *Report, code Code, seq int64) bool {
	for _, f := range rep.Failures {
		if f.Code == code && f.Sequence == seq {
			return true
		}
	}
	return false
}

func TestValidChain(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 200, integrity.ZeroHash)
	o := opts(keySet(t, signer))
	o.Head = headOf(items)
	rep := run(t, items, o)
	expectValid(t, rep)
	if rep.EventsChecked != 200 || rep.FirstSequence != 1 || rep.LastSequence != 200 || rep.PayloadsChecked != 200 {
		t.Fatalf("unexpected counts: %+v", rep)
	}
	want := Checks{HashChain: StatusValid, PayloadHashes: StatusValid, Signatures: StatusValid,
		Ordering: StatusValid, Checkpoints: StatusSkipped, StreamHead: StatusValid}
	if rep.Checks != want {
		t.Fatalf("checks: %+v", rep.Checks)
	}
	if len(rep.KeysUsed) != 1 || rep.KeysUsed[0] != signer.KeyID() {
		t.Fatalf("keys used: %v", rep.KeysUsed)
	}
}

func TestEmptyAndSingleEventStreams(t *testing.T) {
	signer := newSigner(t)
	o := opts(keySet(t, signer))
	o.Head = &Head{}
	expectValid(t, run(t, nil, o))

	o.Head = &Head{Sequence: 3, Hash: integrity.TaggedHash(integrity.TagEvent, []byte("x"))}
	expectFailure(t, run(t, nil, o), CodeHeadMismatch, 3)

	one := buildChain(t, signer, 1, 1, integrity.ZeroHash)
	o.Head = headOf(one)
	rep := run(t, one, o)
	expectValid(t, rep)
	if rep.FirstSequence != 1 || rep.LastSequence != 1 {
		t.Fatalf("counts: %+v", rep)
	}
}

func TestTamperModifiedPayload(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 100, integrity.ZeroHash))
	items[36].Record.Content = content(t, 37, "user_attacker") // sequence 37
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodePayloadHashMismatch, 37)
	if rep.FailureCount != 1 || rep.Checks.PayloadHashes != StatusInvalid || rep.Checks.HashChain != StatusValid ||
		rep.Checks.Signatures != StatusValid {
		t.Fatalf("only the payload check should fail: %+v %v", rep.Checks, rep.Failures)
	}
}

func TestTamperModifiedActorInIndexColumn(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 60, integrity.ZeroHash))
	items[19].Index.ActorID = "user_innocent" // sequence 20: column changed, content intact
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeIndexedFieldMismatch, 20)
	if rep.FirstFailure.Expected != "user_0" || rep.FirstFailure.Found != "user_innocent" {
		t.Fatalf("expected/found: %+v", rep.FirstFailure)
	}
}

func TestTamperNonCanonicalEncoding(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 10, integrity.ZeroHash))
	items[4].Record.Content = append([]byte(" "), items[4].Record.Content...)
	expectFailure(t, run(t, items, opts(keySet(t, signer))), CodePayloadNotCanonical, 5)
	// Outside database mode only semantics matter.
	o := opts(keySet(t, signer))
	o.RequireCanonicalContent = false
	expectValid(t, run(t, items, o))
}

func TestTamperChangedTimestamp(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 50, integrity.ZeroHash))
	items[29].Record.RecordedAt = integrity.FormatTime(baseTime.Add(29*time.Second + time.Millisecond)) // sequence 30
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeEventHashMismatch, 30)
	if rep.FailureCount != 1 {
		t.Fatalf("expected exactly one failure: %v", rep.Failures)
	}
	// Moving it before its predecessor additionally breaks ordering.
	items[29].Record.RecordedAt = integrity.FormatTime(baseTime)
	rep = run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeEventHashMismatch, 30)
	if !hasFailure(rep, CodeTimestampRegression, 30) {
		t.Fatalf("expected timestamp regression: %v", rep.Failures)
	}
}

func TestTamperDeletedEvent(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 100, integrity.ZeroHash)
	head := headOf(items)
	tampered := append(clone(items[:49]), clone(items[50:])...) // delete sequence 50
	o := opts(keySet(t, signer))
	o.Head = head
	rep := run(t, tampered, o)
	expectFailure(t, rep, CodeSequenceGap, 51)
	if !hasFailure(rep, CodePreviousHashMismatch, 51) {
		t.Fatalf("deleting an event must also break the link: %v", rep.Failures)
	}
	if rep.FirstFailure.Expected != "50" || rep.FirstFailure.Found != "51" {
		t.Fatalf("expected/found: %+v", rep.FirstFailure)
	}
	if rep.FailureCount != 2 {
		t.Fatalf("events after the gap are otherwise intact: %v", rep.Failures)
	}
}

func TestTamperSwappedEvents(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 120, integrity.ZeroHash))
	// Swap events 80 and 81 by exchanging their sequence numbers, as an UPDATE
	// of the sequence column would.
	a, b := items[79], items[80]
	a.Record.Sequence, b.Record.Sequence = 81, 80
	items[79], items[80] = b, a
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodePreviousHashMismatch, 80)
	for _, want := range []struct {
		code Code
		seq  int64
	}{{CodeEventHashMismatch, 80}, {CodeEventHashMismatch, 81}, {CodePreviousHashMismatch, 81}, {CodeTimestampRegression, 81}} {
		if !hasFailure(rep, want.code, want.seq) {
			t.Errorf("missing %s at %d: %v", want.code, want.seq, rep.Failures)
		}
	}
	for _, f := range rep.Failures {
		if f.Code == CodePreviousHashMismatch && f.Sequence == 81 && !strings.Contains(f.Message, "sequence 79 instead of 80") {
			t.Errorf("reordering should be explained, got %q", f.Message)
		}
	}
}

func TestTamperChangedPreviousHash(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 80, integrity.ZeroHash))
	items[59].Record.PreviousHash[0] ^= 0x01 // sequence 60
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodePreviousHashMismatch, 60)
	if !hasFailure(rep, CodeEventHashMismatch, 60) {
		t.Fatalf("previousHash is part of the signed header: %v", rep.Failures)
	}
	// An attacker who also recomputes the event hash cannot re-sign it, and
	// the successor no longer links.
	rehash(t, &items[59])
	rep = run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodePreviousHashMismatch, 60)
	if !hasFailure(rep, CodeSignatureInvalid, 60) || !hasFailure(rep, CodePreviousHashMismatch, 61) {
		t.Fatalf("expected signature failure and broken successor link: %v", rep.Failures)
	}
}

func TestTamperForgedSignature(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 30, integrity.ZeroHash))
	forged := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(forged)
	items[9].Record.Signature = forged // sequence 10
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeSignatureInvalid, 10)
	if rep.FailureCount != 1 || rep.Checks.Signatures != StatusInvalid {
		t.Fatalf("only the signature check should fail: %v", rep.Failures)
	}
	// Truncated signatures are rejected too.
	items[9].Record.Signature = forged[:10]
	expectFailure(t, run(t, items, opts(keySet(t, signer))), CodeSignatureInvalid, 10)
}

func TestTamperInsertedForgedEvent(t *testing.T) {
	signer := newSigner(t)
	attacker := newSigner(t)
	items := buildChain(t, signer, 1, 60, integrity.ZeroHash)

	// A perfectly linked forged event at the tail, signed by another key.
	forged := buildChain(t, attacker, 61, 1, items[59].Record.EventHash)
	o := opts(keySet(t, signer))
	o.Head = headOf(items) // the attacker did not (or could not) move the head
	rep := run(t, append(clone(items), forged...), o)
	expectFailure(t, rep, CodeUnknownSigningKey, 61)
	if !hasFailure(rep, CodeHeadMismatch, 61) {
		t.Fatalf("an event beyond the recorded head must be flagged: %v", rep.Failures)
	}

	// A forged event in the middle, with the following events renumbered.
	middle := buildChain(t, attacker, 31, 1, items[29].Record.EventHash)
	tampered := append(clone(items[:30]), middle...)
	for _, it := range clone(items[30:]) {
		it.Record.Sequence++
		tampered = append(tampered, it)
	}
	rep = run(t, tampered, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeUnknownSigningKey, 31)
	if !hasFailure(rep, CodePreviousHashMismatch, 32) || !hasFailure(rep, CodeEventHashMismatch, 32) {
		t.Fatalf("renumbered successors must fail: %v", rep.Failures)
	}
}

func TestTamperSequenceGap(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 40, integrity.ZeroHash))
	items[39].Record.Sequence = 45
	rep := run(t, items, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeSequenceGap, 45)
	if !hasFailure(rep, CodeEventHashMismatch, 45) {
		t.Fatalf("the sequence is part of the signed header: %v", rep.Failures)
	}
}

func TestWrongPublicKey(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 25, integrity.ZeroHash)
	rep := run(t, items, opts(keySet(t, newSigner(t))))
	expectFailure(t, rep, CodeUnknownSigningKey, 1)
	if rep.FailureCount != 25 || rep.Checks.Signatures != StatusInvalid {
		t.Fatalf("every event should fail key lookup: %d", rep.FailureCount)
	}

	// Claiming the trusted key's id while signing with another key fails the
	// signature check.
	attacker := newSigner(t)
	impostor := clone(items)
	impostor[4].Record.KeyID = signer.KeyID()
	h, _ := impostor[4].Record.Header.Hash()
	impostor[4].Record.EventHash = h
	sig, _ := attacker.Sign(context.Background(), integrity.SigningMessage(integrity.TagEventSignature, h))
	impostor[4].Record.Signature = sig
	rep = run(t, impostor, opts(keySet(t, signer)))
	expectFailure(t, rep, CodeSignatureInvalid, 5)
}

func TestKeyRotation(t *testing.T) {
	k1, k2 := newSigner(t), newSigner(t)
	first := buildChain(t, k1, 1, 100, integrity.ZeroHash)
	second := buildChain(t, k2, 101, 100, first[99].Record.EventHash)
	items := append(clone(first), second...)

	pk1 := integrity.NewPublicKey(k1.PublicKey())
	pk1.Status = integrity.KeyStatusRetired
	pk1.ActivatedAt = integrity.FormatTime(baseTime)
	pk1.RetiredAt = first[99].Record.RecordedAt
	pk2 := integrity.NewPublicKey(k2.PublicKey())
	pk2.ActivatedAt = first[99].Record.RecordedAt
	both, err := integrity.NewKeySet(pk1, pk2)
	if err != nil {
		t.Fatal(err)
	}
	o := opts(both)
	o.Head = headOf(items)
	rep := run(t, items, o)
	expectValid(t, rep)
	if len(rep.KeysUsed) != 2 || len(rep.Warnings) != 0 {
		t.Fatalf("keys used %v warnings %v", rep.KeysUsed, rep.Warnings)
	}

	// Without the retired key, history before the rotation is unverifiable.
	onlyNew, _ := integrity.NewKeySet(pk2)
	expectFailure(t, run(t, items, opts(onlyNew)), CodeUnknownSigningKey, 1)

	// Using the retired key after rotation is reported (warning, clock skew aside).
	late := buildChain(t, k1, 201, 1, second[99].Record.EventHash)
	late[0].Record.RecordedAt = integrity.FormatTime(baseTime.Add(time.Hour))
	h, _ := late[0].Record.Header.Hash()
	late[0].Record.EventHash = h
	sig, _ := k1.Sign(context.Background(), integrity.SigningMessage(integrity.TagEventSignature, h))
	late[0].Record.Signature = sig
	rep = run(t, append(clone(items), late...), opts(both))
	expectValid(t, rep)
	if len(rep.Warnings) != 1 || rep.Warnings[0].Code != CodeKeyOutsideValidity {
		t.Fatalf("expected a validity warning: %v", rep.Warnings)
	}

	// A revoked key is an error for events recorded after the revocation.
	pk1.RevokedAt = integrity.FormatTime(baseTime.Add(30 * time.Second))
	revoked, _ := integrity.NewKeySet(pk1, pk2)
	ro := opts(revoked)
	ro.ClockSkew = time.Second
	rep = run(t, items, ro)
	// Event 31 is recorded exactly at revocation + skew; event 32 is the first after it.
	expectFailure(t, rep, CodeSigningKeyRevoked, 32)
}

func TestTruncationAndCheckpoints(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 200, integrity.ZeroHash)
	cp := func(seq int64) integrity.Checkpoint {
		c, err := integrity.NewCheckpoint(context.Background(), signer, fmt.Sprintf("chk_01JDELILCHECKPOINT%05d", seq),
			tenantID, projectID, stream, seq, items[seq-1].Record.EventHash, baseTime.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	o := opts(keySet(t, signer))
	o.Head = headOf(items)
	o.Checkpoints = []integrity.Checkpoint{cp(100), cp(195)}
	rep := run(t, items, o)
	expectValid(t, rep)
	if rep.CheckpointsVerified != 2 || rep.Checks.Checkpoints != StatusValid {
		t.Fatalf("checkpoints: %+v", rep)
	}

	// Truncate the last ten events but keep the stored head and checkpoints.
	rep = run(t, clone(items[:190]), o)
	expectFailure(t, rep, CodeHeadMismatch, 191)
	if !hasFailure(rep, CodeCheckpointBeyondHead, 195) {
		t.Fatalf("checkpoint beyond the end must be reported: %v", rep.Failures)
	}

	// A truncation that also rewrote the head pointer is still caught by the checkpoint.
	o2 := o
	o2.Head = headOf(items[:190])
	rep = run(t, clone(items[:190]), o2)
	expectFailure(t, rep, CodeCheckpointBeyondHead, 195)

	// A tampered checkpoint is rejected rather than trusted.
	bad := cp(100)
	bad.HeadHash[0] ^= 1
	o3 := opts(keySet(t, signer))
	o3.Checkpoints = []integrity.Checkpoint{bad}
	expectFailure(t, run(t, items, o3), CodeCheckpointInvalid, 100)
}

// An attacker who holds the signing key can rebuild a fully valid chain. Only
// a checkpoint kept outside their reach (a witness) reveals the rewrite.
func TestWitnessDetectsRewrittenHistory(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 200, integrity.ZeroHash)
	witness, err := integrity.NewCheckpoint(context.Background(), signer, "chk_01JDELILWITNESS000000150",
		tenantID, projectID, stream, 150, items[149].Record.EventHash, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	rewritten := clone(items[:119])
	prev := rewritten[118].Record.EventHash
	for seq := int64(120); seq <= 200; seq++ {
		c := content(t, int(seq), "user_rewritten")
		rec, err := integrity.Seal(context.Background(), integrity.SealInput{
			TenantID: tenantID, ProjectID: projectID, Stream: stream, Sequence: seq, EventID: eventID(int(seq)),
			RecordedAt: baseTime.Add(time.Duration(seq) * time.Second), PreviousHash: prev, CanonicalContent: c,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		rewritten = append(rewritten, Item{Record: rec})
		prev = rec.EventHash
	}
	o := opts(keySet(t, signer))
	o.Head = headOf(rewritten) // the attacker updated the head too
	expectValid(t, run(t, rewritten, o))

	o.Witnesses = []integrity.Checkpoint{witness}
	rep := run(t, rewritten, o)
	expectFailure(t, rep, CodeCheckpointMismatch, 150)
	if !strings.Contains(rep.FirstFailure.Message, "witness") {
		t.Fatalf("message should mention the witness: %s", rep.FirstFailure.Message)
	}
}

func TestContextMismatchAndAnchors(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 50, integrity.ZeroHash)
	o := opts(keySet(t, signer))
	o.Stream = "payments"
	expectFailure(t, run(t, items, o), CodeContextMismatch, 1)

	// A partial chain anchored at a checkpointed head.
	anchor := &Anchor{Sequence: 20, Hash: items[19].Record.EventHash, Description: "checkpoint chk_x"}
	o = opts(keySet(t, signer))
	o.Anchor = anchor
	rep := run(t, items[20:], o)
	expectValid(t, rep)
	if rep.FirstSequence != 21 || rep.Anchor != "checkpoint chk_x" {
		t.Fatalf("anchor: %+v", rep)
	}
	o.Anchor = &Anchor{Sequence: 20, Hash: items[18].Record.EventHash, Description: "wrong"}
	expectFailure(t, run(t, items[20:], o), CodeAnchorMismatch, 21)
	// Starting a whole-stream verification mid-chain is a gap.
	expectFailure(t, run(t, items[5:], opts(keySet(t, signer))), CodeSequenceGap, 6)
}

func TestHeaderOnlyRecords(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 30, integrity.ZeroHash)
	headers := make([]Item, len(items))
	for i, it := range items {
		headers[i] = Item{Record: it.Record.WithoutContent()}
	}
	o := opts(keySet(t, signer))
	o.RequireContent, o.RequireCanonicalContent = false, false
	rep := run(t, headers, o)
	expectValid(t, rep)
	if rep.Checks.PayloadHashes != StatusSkipped || rep.PayloadsChecked != 0 {
		t.Fatalf("payload check should be skipped: %+v", rep.Checks)
	}
	o.RequireContent = true
	expectFailure(t, run(t, headers, o), CodePayloadMissing, 1)
}

func TestParallelAndSequentialAgree(t *testing.T) {
	signer := newSigner(t)
	items := clone(buildChain(t, signer, 1, 500, integrity.ZeroHash))
	items[100].Record.Content = content(t, 1, "x")
	items[300].Record.Signature[5] ^= 1
	items = append(items[:200], items[201:]...)
	var reports []*Report
	for _, p := range []int{1, 3, 8} {
		o := opts(keySet(t, signer))
		o.Parallelism = p
		o.Now = func() time.Time { return baseTime }
		reports = append(reports, run(t, items, o))
	}
	for _, r := range reports[1:] {
		if fmt.Sprint(r.Failures) != fmt.Sprint(reports[0].Failures) {
			t.Fatalf("parallelism changed the result:\n%v\n%v", reports[0].Failures, r.Failures)
		}
	}
}

func TestFailureCap(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 300, integrity.ZeroHash)
	o := opts(keySet(t, newSigner(t)))
	o.MaxFailures = 10
	rep := run(t, items, o)
	if rep.FailureCount != 300 || len(rep.Failures) != 10 || !rep.FailuresTruncated {
		t.Fatalf("cap: count=%d listed=%d truncated=%v", rep.FailureCount, len(rep.Failures), rep.FailuresTruncated)
	}
	if rep.Checks.Signatures != StatusInvalid {
		t.Fatal("status must reflect truncated failures")
	}
}

func TestVerifyEvent(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 60, integrity.ZeroHash)
	eo := EventOptions{TenantID: tenantID, ProjectID: projectID, Stream: stream, Keys: keySet(t, signer),
		RequireCanonicalContent: true}

	rep := VerifyEvent(items[49], &items[48], &items[50], eo)
	expectValid(t, rep)
	if rep.Scope != ScopeEvent || rep.EventID != eventID(50) {
		t.Fatalf("report: %+v", rep)
	}
	expectValid(t, VerifyEvent(items[0], nil, &items[1], eo))
	expectValid(t, VerifyEvent(items[59], &items[58], nil, eo))

	tampered := clone(items)
	tampered[49].Record.Content = content(t, 999, "x")
	expectFailure(t, VerifyEvent(tampered[49], &tampered[48], &tampered[50], eo), CodePayloadHashMismatch, 50)

	expectFailure(t, VerifyEvent(items[49], nil, &items[50], eo), CodeSequenceGap, 50)

	broken := clone(items)
	broken[50].Record.PreviousHash[3] ^= 1
	rep = VerifyEvent(items[49], &items[48], &broken[50], eo)
	if rep.Valid || !hasFailure(rep, CodePreviousHashMismatch, 51) {
		t.Fatalf("a broken successor link must be reported: %v", rep.Failures)
	}
}

func TestWriteText(t *testing.T) {
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 20, integrity.ZeroHash)
	var buf bytes.Buffer
	WriteText(&buf, run(t, items, opts(keySet(t, signer))), Style{})
	out := buf.String()
	for _, want := range []string{"DƏLİL Integrity Verification", "Events checked:    20", "Hash chain:        VALID",
		"Digital signatures:VALID", "Tampering detected: NO", "Verification completed successfully."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	buf.Reset()
	bad := clone(items)
	bad[11].Record.PreviousHash[0] ^= 1
	WriteText(&buf, run(t, bad, opts(keySet(t, signer))), Style{})
	out = buf.String()
	for _, want := range []string{"Verification FAILED", "Sequence:  12", "previous hash mismatch",
		"cannot be cryptographically trusted", "Tampering detected: YES"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if Thousands(18421) != "18,421" || Thousands(1000000) != "1,000,000" || Thousands(999) != "999" {
		t.Fatal("thousands separator")
	}
}

func TestVeryLargeStream(t *testing.T) {
	if testing.Short() {
		t.Skip("large stream test skipped in -short mode")
	}
	signer := newSigner(t)
	items := buildChain(t, signer, 1, 100_000, integrity.ZeroHash)
	o := opts(keySet(t, signer))
	o.Head = headOf(items)
	start := time.Now()
	rep, err := VerifyStream(context.Background(), &SliceSource{Items: items, BatchSize: 2000}, o)
	if err != nil {
		t.Fatal(err)
	}
	expectValid(t, rep)
	if rep.EventsChecked != 100_000 {
		t.Fatalf("checked %d", rep.EventsChecked)
	}
	t.Logf("verified 100,000 events in %s", time.Since(start).Round(time.Millisecond))
}

func BenchmarkVerifyStream(b *testing.B) {
	signer := newSigner(b)
	items := buildChain(b, signer, 1, 10_000, integrity.ZeroHash)
	o := opts(keySet(b, signer))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyStream(context.Background(), &SliceSource{Items: items, BatchSize: 2000}, o); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(10_000*b.N)/b.Elapsed().Seconds(), "events/s")
}
