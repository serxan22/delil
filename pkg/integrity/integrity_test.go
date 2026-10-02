package integrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/serxan22/delil/pkg/jcs"
)

var update = flag.Bool("update", false, "rewrite docs/test-vectors.json")

const vectorsPath = "../../docs/test-vectors.json"

func testSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	s, err := NewEd25519SignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustCanonical(t *testing.T, raw string) []byte {
	t.Helper()
	out, err := jcs.Canonicalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sealFixture(t *testing.T, signer Signer, seq int64, prev Hash, eventID string, at time.Time, content string) Record {
	t.Helper()
	rec, err := Seal(context.Background(), SealInput{
		TenantID:         "org_01JDELILTENANT0000000000",
		ProjectID:        "prj_01JDELILPROJECT000000000",
		Stream:           "contracts",
		Sequence:         seq,
		EventID:          eventID,
		RecordedAt:       at,
		PreviousHash:     prev,
		CanonicalContent: mustCanonical(t, content),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestSealProducesVerifiableRecord(t *testing.T) {
	signer := testSigner(t)
	at := time.Date(2026, 10, 2, 9, 15, 0, 123456789, time.UTC)
	rec := sealFixture(t, signer, 1, ZeroHash, "evt_01JDELILEVENT00000000001", at,
		`{"action":"contract.approved","actor":{"id":"user_128","type":"user"}}`)

	if rec.RecordedAt != "2026-10-02T09:15:00.123456Z" {
		t.Fatalf("recordedAt must be truncated to microseconds, got %s", rec.RecordedAt)
	}
	if !rec.PayloadHash.Equal(PayloadHash(rec.Content)) {
		t.Fatal("payload hash does not match content")
	}
	h, err := rec.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if !h.Equal(rec.EventHash) {
		t.Fatal("event hash does not match header")
	}
	if !VerifySignature(signer.PublicKey(), TagEventSignature, rec.EventHash, rec.Signature) {
		t.Fatal("signature does not verify")
	}
	// Changing any header field changes the event hash.
	mutations := map[string]func(*Header){
		"tenant":    func(h *Header) { h.TenantID = "org_01JDELILTENANT0000000001" },
		"project":   func(h *Header) { h.ProjectID = "prj_01JDELILPROJECT000000001" },
		"stream":    func(h *Header) { h.Stream = "payments" },
		"sequence":  func(h *Header) { h.Sequence = 2 },
		"eventId":   func(h *Header) { h.EventID = "evt_01JDELILEVENT00000000002" },
		"time":      func(h *Header) { h.RecordedAt = "2026-10-02T09:15:00.123457Z" },
		"previous":  func(h *Header) { h.PreviousHash[0] ^= 1 },
		"payload":   func(h *Header) { h.PayloadHash[31] ^= 1 },
		"keyId":     func(h *Header) { h.KeyID = "ed25519:00000000000000000000000000000000" },
		"schemaVer": func(h *Header) { h.SchemaVersion = 2 },
	}
	for name, mutate := range mutations {
		hdr := rec.Header
		mutate(&hdr)
		canonical, err := hdr.Canonical()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if TaggedHash(TagEvent, canonical).Equal(rec.EventHash) {
			t.Errorf("mutating %s did not change the event hash", name)
		}
	}
}

func TestSealRejectsInvalidHeaders(t *testing.T) {
	signer := testSigner(t)
	base := SealInput{
		TenantID: "org_01JDELILTENANT0000000000", ProjectID: "prj_01JDELILPROJECT000000000",
		Stream: "contracts", Sequence: 1, EventID: "evt_01JDELILEVENT00000000001",
		RecordedAt: time.Now(), CanonicalContent: []byte(`{}`),
	}
	cases := map[string]func(*SealInput){
		"zero sequence":         func(in *SealInput) { in.Sequence = 0 },
		"bad stream":            func(in *SealInput) { in.Stream = "Contracts!" },
		"bad tenant":            func(in *SealInput) { in.TenantID = "tenant" },
		"bad event id":          func(in *SealInput) { in.EventID = "" },
		"genesis with previous": func(in *SealInput) { in.PreviousHash[0] = 1 },
	}
	for name, mutate := range cases {
		in := base
		mutate(&in)
		if _, err := Seal(context.Background(), in, signer); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

type brokenSigner struct{ *Ed25519Signer }

func (b brokenSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	sig, _ := b.Ed25519Signer.Sign(ctx, msg)
	sig[0] ^= 0xff
	return sig, nil
}

func TestSealRejectsBadSigner(t *testing.T) {
	_, err := Seal(context.Background(), SealInput{
		TenantID: "org_01JDELILTENANT0000000000", ProjectID: "prj_01JDELILPROJECT000000000",
		Stream: "contracts", Sequence: 1, EventID: "evt_01JDELILEVENT00000000001",
		RecordedAt: time.Now(), CanonicalContent: []byte(`{}`),
	}, brokenSigner{testSigner(t)})
	if err == nil {
		t.Fatal("a signer producing invalid signatures must be detected before commit")
	}
}

func TestDomainSeparation(t *testing.T) {
	signer := testSigner(t)
	h := TaggedHash(TagEvent, []byte(`{}`))
	sig, _ := signer.Sign(context.Background(), SigningMessage(TagEventSignature, h))
	if VerifySignature(signer.PublicKey(), TagCheckpointSignature, h, sig) {
		t.Fatal("an event signature must not verify as a checkpoint signature")
	}
	if VerifySignature(signer.PublicKey(), TagManifestSignature, h, sig) {
		t.Fatal("an event signature must not verify as a manifest signature")
	}
	if TaggedHash(TagPayload, []byte("x")) == TaggedHash(TagEvent, []byte("x")) {
		t.Fatal("payload and event hashes of identical bytes must differ")
	}
}

func TestHashText(t *testing.T) {
	h := TaggedHash(TagPayload, []byte("delil"))
	parsed, err := ParseHash(h.String())
	if err != nil || parsed != h {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, bad := range []string{strings.ToUpper(h.String()), h.String()[:63], h.String() + "0", "zz" + h.String()[2:]} {
		if _, err := ParseHash(bad); err == nil {
			t.Errorf("ParseHash(%q) should fail", bad)
		}
	}
	var decoded struct{ H Hash }
	if err := json.Unmarshal([]byte(`{"H":"`+h.String()+`"}`), &decoded); err != nil || decoded.H != h {
		t.Fatalf("JSON round trip failed: %v", err)
	}
}

func TestTimeFormat(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6789, time.FixedZone("AZT", 4*3600))
	got := FormatTime(ts)
	if got != "2026-01-01T23:04:05.000006Z" {
		t.Fatalf("got %s", got)
	}
	if _, err := ParseTime(got); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"2026-01-01T23:04:05Z", "2026-01-01T23:04:05.000006+00:00", "2026-01-01 23:04:05.000006Z", "2026-01-01T23:04:05.0000060Z"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("ParseTime(%q) should fail", bad)
		}
	}
}

func TestKeySet(t *testing.T) {
	signer := testSigner(t)
	pk := NewPublicKey(signer.PublicKey())
	if pk.KeyID != signer.KeyID() || !strings.HasPrefix(pk.KeyID, "ed25519:") || len(pk.KeyID) != 40 {
		t.Fatalf("unexpected key id %q", pk.KeyID)
	}
	set, err := NewKeySet(pk, pk)
	if err != nil || set.Len() != 1 {
		t.Fatalf("duplicate identical keys should collapse: %v", err)
	}
	wrongID := pk
	wrongID.KeyID = "ed25519:ffffffffffffffffffffffffffffffff"
	if _, err := NewKeySet(wrongID); err == nil {
		t.Fatal("a key whose id does not derive from its material must be rejected")
	}
	wrongFP := pk
	wrongFP.Fingerprint = strings.Repeat("0", 64)
	if _, err := NewKeySet(wrongFP); err == nil {
		t.Fatal("a key whose fingerprint does not match must be rejected")
	}
	short := pk
	short.PublicKey = short.PublicKey[:31]
	if _, err := NewKeySet(short); err == nil {
		t.Fatal("short keys must be rejected")
	}
}

func TestKeyUsageWindows(t *testing.T) {
	pk := NewPublicKey(testSigner(t).PublicKey())
	pk.ActivatedAt = "2026-01-01T00:00:00.000000Z"
	pk.RetiredAt = "2026-06-01T00:00:00.000000Z"
	skew := time.Minute
	at := func(s string) time.Time { t1, _ := ParseTime(s); return t1 }
	cases := map[string]KeyUsage{
		"2026-03-01T00:00:00.000000Z": KeyUsageValid,
		"2025-12-31T23:59:30.000000Z": KeyUsageValid, // within skew
		"2025-12-31T00:00:00.000000Z": KeyUsageBeforeActivation,
		"2026-06-01T00:00:30.000000Z": KeyUsageValid, // within skew
		"2026-07-01T00:00:00.000000Z": KeyUsageAfterRetirement,
	}
	for ts, want := range cases {
		if got := pk.UsageAt(at(ts), skew); got != want {
			t.Errorf("%s: got %v want %v", ts, got, want)
		}
	}
	pk.RevokedAt = "2026-04-01T00:00:00.000000Z"
	if got := pk.UsageAt(at("2026-05-01T00:00:00.000000Z"), skew); got != KeyUsageAfterRevocation {
		t.Errorf("revoked: got %v", got)
	}
}

func TestCheckpoint(t *testing.T) {
	signer := testSigner(t)
	head := TaggedHash(TagEvent, []byte("head"))
	cp, err := NewCheckpoint(context.Background(), signer, "chk_01JDELILCHECKPOINT00001",
		"org_01JDELILTENANT0000000000", "prj_01JDELILPROJECT000000000", "contracts", 1000, head,
		time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := NewKeySet(NewPublicKey(signer.PublicKey()))
	if err := cp.Verify(keys); err != nil {
		t.Fatalf("fresh checkpoint must verify: %v", err)
	}
	tampered := cp
	tampered.Sequence = 999
	if err := tampered.Verify(keys); !errors.Is(err, ErrCheckpointHash) {
		t.Fatalf("expected hash error, got %v", err)
	}
	forged := cp
	forged.Sequence = 999
	forged.CheckpointHash, _ = forged.ComputeHash()
	if err := forged.Verify(keys); !errors.Is(err, ErrCheckpointSignature) {
		t.Fatalf("expected signature error, got %v", err)
	}
	empty, _ := NewKeySet()
	if err := cp.Verify(empty); !errors.Is(err, ErrCheckpointUnknownKey) {
		t.Fatalf("expected unknown key error, got %v", err)
	}
	// JSON round trip keeps it verifiable.
	raw, _ := json.Marshal(cp)
	var decoded Checkpoint
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(keys); err != nil {
		t.Fatalf("decoded checkpoint must verify: %v", err)
	}
}

func TestParseContentAndIndex(t *testing.T) {
	raw := mustCanonical(t, `{"action":"refund.issued","actor":{"type":"user","id":"u1","displayName":"Nigar"},
		"resource":{"type":"invoice","id":"inv_9"},"before":null,"after":{"status":"refunded"},
		"occurredAt":"2026-10-01T08:00:00.000000Z","futureField":true}`)
	c, err := ParseContent(raw)
	if err != nil {
		t.Fatal(err)
	}
	idx := c.Index()
	want := IndexFields{ActorType: "user", ActorID: "u1", Action: "refund.issued",
		ResourceType: "invoice", ResourceID: "inv_9", OccurredAt: "2026-10-01T08:00:00.000000Z"}
	if idx != want {
		t.Fatalf("got %+v", idx)
	}
	if string(c.Before) != "null" {
		t.Fatalf("explicit null must be preserved, got %q", c.Before)
	}
	other := want
	other.ActorID = "u2"
	if d := idx.Diff(other); len(d) != 1 || d[0] != "actor_id" {
		t.Fatalf("diff: %v", d)
	}
	if _, err := ParseContent([]byte(`{"action":"x","action":"y"}`)); err == nil {
		t.Fatal("duplicate members must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Known-answer test vectors

type vectorFile struct {
	Description  string           `json:"description"`
	Schema       int              `json:"schemaVersion"`
	Construction []string         `json:"construction"`
	SigningKey   vectorKey        `json:"signingKey"`
	Events       []vectorEvent    `json:"events"`
	Checkpoint   vectorCheckpoint `json:"checkpoint"`
}

type vectorKey struct {
	SeedHex     string `json:"seedHex"`
	PublicKey   string `json:"publicKeyBase64"`
	Fingerprint string `json:"fingerprint"`
	KeyID       string `json:"keyId"`
}

type vectorEvent struct {
	Name              string          `json:"name"`
	Content           json.RawMessage `json:"content"`
	ContentCanonical  string          `json:"contentCanonical"`
	PayloadHash       string          `json:"payloadHash"`
	Header            json.RawMessage `json:"header"`
	HeaderCanonical   string          `json:"headerCanonical"`
	EventHash         string          `json:"eventHash"`
	SigningMessageHex string          `json:"signingMessageHex"`
	Signature         string          `json:"signatureBase64"`
}

type vectorCheckpoint struct {
	Body           json.RawMessage `json:"body"`
	BodyCanonical  string          `json:"bodyCanonical"`
	CheckpointHash string          `json:"checkpointHash"`
	Signature      string          `json:"signatureBase64"`
}

func buildVectors(t *testing.T) vectorFile {
	signer := testSigner(t)
	pub := signer.PublicKey()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	out := vectorFile{
		Description: "DELIL integrity schema v1 known-answer vectors. Regenerate with: go test ./pkg/integrity -run TestKnownAnswerVectors -update",
		Schema:      SchemaVersion,
		Construction: []string{
			"payloadHash = SHA-256(\"delil:v1:payload\" || 0x00 || JCS(content))",
			"eventHash = SHA-256(\"delil:v1:event\" || 0x00 || JCS(header))",
			"signature = Ed25519(seed, \"delil:v1:event-signature\" || 0x00 || eventHash)",
			"checkpointHash = SHA-256(\"delil:v1:checkpoint\" || 0x00 || JCS(checkpointBody))",
			"checkpointSignature = Ed25519(seed, \"delil:v1:checkpoint-signature\" || 0x00 || checkpointHash)",
			"keyId = \"ed25519:\" || first 32 hex chars of SHA-256(rawPublicKey)",
		},
		SigningKey: vectorKey{
			SeedHex:     hex.EncodeToString(seed),
			PublicKey:   base64.StdEncoding.EncodeToString(pub),
			Fingerprint: Fingerprint(pub),
			KeyID:       KeyIDFor(pub),
		},
	}
	contents := []struct{ name, content string }{
		{"genesis event", `{"action":"contract.created","actor":{"displayName":"Sarkhan Mahabbatli","id":"user_128","type":"user"},"after":{"status":"draft","value":{"amount":12500.5,"currency":"AZN"}},"before":null,"changes":[{"op":"add","path":"/status","to":"draft"},{"op":"add","path":"/value","to":{"amount":12500.5,"currency":"AZN"}}],"resource":{"id":"contract_813","type":"contract"}}`},
		{"second event", `{"action":"contract.approved","actor":{"id":"user_128","type":"user"},"after":{"status":"approved"},"before":{"status":"draft"},"changes":[{"from":"draft","op":"replace","path":"/status","to":"approved"}],"context":{"requestId":"req_123","sourceIp":"203.0.113.7"},"metadata":{"note":"Dəlil — €"},"occurredAt":"2026-10-02T09:14:59.000000Z","resource":{"id":"contract_813","type":"contract"}}`},
	}
	prev := ZeroHash
	base := time.Date(2026, 10, 2, 9, 15, 0, 0, time.UTC)
	for i, c := range contents {
		eventID := []string{"evt_01JDELILVECTOR000000001", "evt_01JDELILVECTOR000000002"}[i]
		rec := sealFixture(t, signer, int64(i+1), prev, eventID, base.Add(time.Duration(i)*time.Second), c.content)
		headerCanonical, err := rec.Header.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		out.Events = append(out.Events, vectorEvent{
			Name:              c.name,
			Content:           json.RawMessage(rec.Content),
			ContentCanonical:  string(rec.Content),
			PayloadHash:       rec.PayloadHash.String(),
			Header:            json.RawMessage(headerCanonical),
			HeaderCanonical:   string(headerCanonical),
			EventHash:         rec.EventHash.String(),
			SigningMessageHex: hex.EncodeToString(SigningMessage(TagEventSignature, rec.EventHash)),
			Signature:         rec.Signature.String(),
		})
		prev = rec.EventHash
	}
	cp, err := NewCheckpoint(context.Background(), signer, "chk_01JDELILVECTOR000000001",
		"org_01JDELILTENANT0000000000", "prj_01JDELILPROJECT000000000", "contracts", 2, prev,
		base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := cp.Canonical()
	out.Checkpoint = vectorCheckpoint{
		Body:           json.RawMessage(body),
		BodyCanonical:  string(body),
		CheckpointHash: cp.CheckpointHash.String(),
		Signature:      cp.Signature.String(),
	}
	return out
}

func TestKnownAnswerVectors(t *testing.T) {
	got := buildVectors(t)
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("docs/test-vectors.json is out of date or the construction changed.\n" +
			"A change here breaks verification of every existing event; it requires a new schema version.")
	}
	// Independently re-verify the published vectors from their raw fields.
	var file vectorFile
	if err := json.Unmarshal(want, &file); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(file.SigningKey.PublicKey)
	for _, ev := range file.Events {
		canonical, err := jcs.Canonicalize(ev.Content)
		if err != nil || string(canonical) != ev.ContentCanonical {
			t.Fatalf("%s: content canonicalization mismatch", ev.Name)
		}
		if PayloadHash(canonical).String() != ev.PayloadHash {
			t.Fatalf("%s: payload hash mismatch", ev.Name)
		}
		eh := TaggedHash(TagEvent, []byte(ev.HeaderCanonical))
		if eh.String() != ev.EventHash {
			t.Fatalf("%s: event hash mismatch", ev.Name)
		}
		sig, _ := base64.StdEncoding.DecodeString(ev.Signature)
		if !VerifySignature(pub, TagEventSignature, eh, sig) {
			t.Fatalf("%s: signature does not verify", ev.Name)
		}
	}
}
