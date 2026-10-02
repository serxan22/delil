package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
	"github.com/serxan22/delil/pkg/verify"
)

const (
	tenantID  = "org_01JDELILTENANT0000000000"
	projectID = "prj_01JDELILPROJECT000000000"
	stream    = "contracts"
)

var base = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func newSigner(t *testing.T) *integrity.Ed25519Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := integrity.NewEd25519Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func chain(t *testing.T, signer integrity.Signer, n int) []integrity.Record {
	t.Helper()
	var out []integrity.Record
	prev := integrity.ZeroHash
	for i := 1; i <= n; i++ {
		actor := fmt.Sprintf("user_%d", i%3)
		c, _ := jcs.Canonicalize([]byte(fmt.Sprintf(`{"action":"contract.updated","actor":{"type":"user","id":%q},"data":{"n":%d}}`, actor, i)))
		rec, err := integrity.Seal(context.Background(), integrity.SealInput{TenantID: tenantID, ProjectID: projectID,
			Stream: stream, Sequence: int64(i), EventID: fmt.Sprintf("evt_01JDELILEVENT%011d", i),
			RecordedAt: base.Add(time.Duration(i) * time.Second), PreviousHash: prev, CanonicalContent: c}, signer)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
		prev = rec.EventHash
	}
	return out
}

type spec struct {
	signer      integrity.Signer
	records     []integrity.Record
	from, to    int64
	anchorAt    int64 // 0 = genesis
	checkpoints []integrity.Checkpoint
	filter      func(integrity.Record) bool
	filters     map[string]string
	// mutateEvent lets a test alter disclosed events inside a correctly
	// signed package (simulating a buggy or malicious producer).
	mutateEvent func(integrity.Record) integrity.Record
}

func checkpointAt(t *testing.T, signer integrity.Signer, records []integrity.Record, seq int64) integrity.Checkpoint {
	t.Helper()
	cp, err := integrity.NewCheckpoint(context.Background(), signer, fmt.Sprintf("chk_01JDELILCHECKPOINT%07d", seq),
		tenantID, projectID, stream, seq, records[seq-1].EventHash, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func build(t *testing.T, s spec) []byte {
	t.Helper()
	var buf bytes.Buffer
	b := NewBuilder(&buf, base.Add(2*time.Hour))
	firstChain := s.anchorAt + 1
	n, err := b.WriteJSONL(FileChain, func(w *JSONLWriter) error {
		for _, r := range s.records[firstChain-1 : s.to] {
			if err := w.Write(r.WithoutContent()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	disclosed, err := b.WriteJSONL(FileEvents, func(w *JSONLWriter) error {
		for _, r := range s.records[s.from-1 : s.to] {
			if s.filter == nil || s.filter(r) {
				if s.mutateEvent != nil {
					r = s.mutateEvent(r)
				}
				if err := w.Write(r); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WriteJSON(FileCheckpoints, CheckpointsFile{Checkpoints: s.checkpoints}); err != nil {
		t.Fatal(err)
	}
	pk := integrity.NewPublicKey(s.signer.PublicKey())
	if err := b.WriteJSON(FilePublicKeys, KeysFile{Keys: []integrity.PublicKey{pk}}); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteJSON(FileVerification, map[string]any{"valid": true}); err != nil {
		t.Fatal(err)
	}
	anchor := ChainAnchor{Type: AnchorGenesis, Sequence: 0, Hash: integrity.ZeroHash.String()}
	if s.anchorAt > 0 {
		anchor = ChainAnchor{Type: AnchorCheckpoint, CheckpointID: fmt.Sprintf("chk_01JDELILCHECKPOINT%07d", s.anchorAt),
			Sequence: s.anchorAt, Hash: s.records[s.anchorAt-1].EventHash.String()}
	}
	m := Manifest{
		PackageID: "exp_01JDELILEXPORT0000000001", CreatedAt: integrity.FormatTime(base.Add(2 * time.Hour)),
		Generator: Generator{Name: "delil-test", Version: "0.0.0"}, Tenant: NamedID{ID: tenantID, Name: "LegalFlow"},
		Project: NamedID{ID: projectID, Name: "Demo"}, Stream: stream,
		Selection: Selection{FromSequence: s.from, ToSequence: s.to, Filters: s.filters, DisclosedEvents: disclosed},
		Chain:     ChainInfo{FirstSequence: firstChain, LastSequence: s.to, Events: n, Anchor: anchor},
	}
	if err := b.WriteFile(FileReadme, []byte(Readme(&m))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Finish(context.Background(), m, s.signer); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func defaultSpec(t *testing.T) spec {
	signer := newSigner(t)
	records := chain(t, signer, 50)
	return spec{signer: signer, records: records, from: 25, to: 40, anchorAt: 20,
		checkpoints: []integrity.Checkpoint{checkpointAt(t, signer, records, 20), checkpointAt(t, signer, records, 30)}}
}

func run(t *testing.T, data []byte, opts Options) *Result {
	t.Helper()
	res, err := Verify(bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func trusted(t *testing.T, signers ...integrity.Signer) *integrity.KeySet {
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

func codes(res *Result) map[verify.Code]bool {
	out := map[verify.Code]bool{}
	for _, f := range res.Failures {
		out[f.Code] = true
	}
	return out
}

// rewrite rebuilds an archive, letting mutate replace or drop entries.
func rewrite(t *testing.T, data []byte, mutate func(name string, content []byte) ([]byte, bool), extra ...[2]string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		rc, _ := f.Open()
		content, _ := io.ReadAll(rc)
		rc.Close()
		if mutate != nil {
			var keep bool
			content, keep = mutate(f.Name, content)
			if !keep {
				continue
			}
		}
		w, _ := zw.Create(f.Name)
		_, _ = w.Write(content)
	}
	for _, e := range extra {
		w, _ := zw.Create(e[0])
		_, _ = w.Write([]byte(e[1]))
	}
	_ = zw.Close()
	return out.Bytes()
}

func readEntry(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	for _, f := range zr.File {
		if f.Name == name {
			rc, _ := f.Open()
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return b
		}
	}
	t.Fatalf("entry %s not found", name)
	return nil
}

func TestValidPackage(t *testing.T) {
	s := defaultSpec(t)
	data := build(t, s)
	res := run(t, data, Options{})
	if !res.Valid {
		t.Fatalf("package must verify: %v", res.Failures)
	}
	if res.KeysTrusted() || res.Package.KeysTrusted {
		t.Fatal("embedded keys must not be reported as trusted")
	}
	if res.EventsChecked != 20 || res.PayloadsChecked != 16 || res.FirstSequence != 21 || res.LastSequence != 40 {
		t.Fatalf("counts: checked=%d payloads=%d %d..%d", res.EventsChecked, res.PayloadsChecked, res.FirstSequence, res.LastSequence)
	}
	if res.Checks.Package != verify.StatusValid || res.Checks.Checkpoints != verify.StatusValid || res.CheckpointsVerified != 2 {
		t.Fatalf("checks: %+v (checkpoints %d)", res.Checks, res.CheckpointsVerified)
	}
	if res.Package.ServerReportedValid == nil || !*res.Package.ServerReportedValid || res.Package.FilesVerified != 6 {
		t.Fatalf("package info: %+v", res.Package)
	}
	pinned := run(t, data, Options{TrustedKeys: trusted(t, s.signer)})
	if !pinned.Valid || !pinned.Package.KeysTrusted {
		t.Fatalf("verification with pinned keys: %v", pinned.Failures)
	}
	if !strings.Contains(readEntryString(t, data, FileReadme), "WHAT IT DOES NOT PROVE") {
		t.Fatal("README must explain the limits")
	}
}

func readEntryString(t *testing.T, data []byte, name string) string {
	return string(readEntry(t, data, name))
}

// KeysTrusted is a convenience for tests.
func (r *Result) KeysTrusted() bool { return r.Package.KeysTrusted }

func TestGenesisAndFilteredPackages(t *testing.T) {
	s := defaultSpec(t)
	s.from, s.to, s.anchorAt = 1, 50, 0
	if res := run(t, build(t, s), Options{}); !res.Valid || res.EventsChecked != 50 || res.Anchor != "genesis" {
		t.Fatalf("genesis package: %v %+v", res.Failures, res.Report)
	}
	s = defaultSpec(t)
	s.filters = map[string]string{"actorId": "user_1"}
	s.filter = func(r integrity.Record) bool { return strings.Contains(string(r.Content), `"user_1"`) }
	res := run(t, build(t, s), Options{})
	if !res.Valid {
		t.Fatalf("filtered package: %v", res.Failures)
	}
	if res.PayloadsChecked == 0 || res.PayloadsChecked >= 16 || res.EventsChecked != 20 {
		t.Fatalf("selective disclosure counts: payloads=%d events=%d", res.PayloadsChecked, res.EventsChecked)
	}
}

func TestPackageIsReproducible(t *testing.T) {
	s := defaultSpec(t)
	if !bytes.Equal(build(t, s), build(t, s)) {
		t.Fatal("identical inputs must produce identical packages")
	}
}

func TestWrongTrustedKeys(t *testing.T) {
	s := defaultSpec(t)
	res := run(t, build(t, s), Options{TrustedKeys: trusted(t, newSigner(t))})
	c := codes(res)
	if res.Valid || !c[verify.CodeManifestSignatureInvalid] || !c[verify.CodeUnknownSigningKey] {
		t.Fatalf("expected key failures, got %v", res.Failures)
	}
}

func TestModifiedFileIsDetected(t *testing.T) {
	data := build(t, defaultSpec(t))
	tampered := rewrite(t, data, func(name string, c []byte) ([]byte, bool) {
		if name == FileEvents {
			return bytes.Replace(c, []byte(`"n":30`), []byte(`"n":31`), 1), true
		}
		return c, true
	})
	res := run(t, tampered, Options{})
	if res.Valid || !codes(res)[verify.CodePackageDigestMismatch] {
		t.Fatalf("expected a digest mismatch, got %v", res.Failures)
	}
}

// An attacker who also updates the manifest digest invalidates the manifest
// signature, and the modified event still fails its payload hash.
func TestModifiedFileWithUpdatedManifest(t *testing.T) {
	s := defaultSpec(t)
	data := build(t, s)
	var newEvents []byte
	tampered := rewrite(t, data, func(name string, c []byte) ([]byte, bool) {
		if name == FileEvents {
			newEvents = bytes.Replace(c, []byte(`"n":30`), []byte(`"n":31`), 1)
			return newEvents, true
		}
		return c, true
	})
	tampered = rewrite(t, tampered, func(name string, c []byte) ([]byte, bool) {
		if name != FileManifest {
			return c, true
		}
		var m Manifest
		_ = json.Unmarshal(c, &m)
		sum := sha256.Sum256(newEvents)
		for i := range m.Files {
			if m.Files[i].Path == FileEvents {
				m.Files[i].SHA256, m.Files[i].Size = hex.EncodeToString(sum[:]), int64(len(newEvents))
			}
		}
		out, _ := json.Marshal(m)
		return out, true
	})
	res := run(t, tampered, Options{TrustedKeys: trusted(t, s.signer)})
	c := codes(res)
	if res.Valid || !c[verify.CodeManifestSignatureInvalid] || !c[verify.CodePayloadHashMismatch] {
		t.Fatalf("expected manifest and payload failures, got %v", res.Failures)
	}
}

// Replacing the embedded keys and re-signing the manifest does not help: the
// events are signed by the real key, and pinned keys reject the manifest.
func TestReplacedKeysAreDetected(t *testing.T) {
	s := defaultSpec(t)
	data := build(t, s)
	attacker := newSigner(t)
	forged := s
	forged.signer = attacker
	// Same records (signed by the real key), but manifest and keys from the attacker.
	res := run(t, build(t, forged), Options{})
	if res.Valid || !codes(res)[verify.CodeUnknownSigningKey] {
		t.Fatalf("events signed by a key missing from the package must fail: %v", res.Failures)
	}
	res = run(t, data, Options{TrustedKeys: trusted(t, attacker)})
	if res.Valid {
		t.Fatal("pinned keys must reject a package signed by someone else")
	}
}

func TestHostileArchives(t *testing.T) {
	data := build(t, defaultSpec(t))
	cases := map[string][]byte{
		"zip slip":          rewrite(t, data, nil, [2]string{"../../etc/cron.d/evil", "x"}),
		"absolute path":     rewrite(t, data, nil, [2]string{"/tmp/evil", "x"}),
		"nested path":       rewrite(t, data, nil, [2]string{"dir/chain.jsonl", "x"}),
		"duplicate entry":   rewrite(t, data, nil, [2]string{FileEvents, "{}"}),
		"unexpected entry":  rewrite(t, data, nil, [2]string{"payload.exe", "x"}),
		"missing chain":     rewrite(t, data, func(n string, c []byte) ([]byte, bool) { return c, n != FileChain }),
		"missing signature": rewrite(t, data, func(n string, c []byte) ([]byte, bool) { return c, n != FileSignature }),
		"not a zip":         []byte("definitely not a zip archive"),
	}
	for name, archive := range cases {
		res := run(t, archive, Options{})
		if res.Valid || !codes(res)[verify.CodePackageMalformed] {
			t.Errorf("%s: expected package_malformed, got %v", name, res.Failures)
		}
	}

	// A zip bomb: a tiny archive that expands far beyond the limits.
	var bomb bytes.Buffer
	zw := zip.NewWriter(&bomb)
	w, _ := zw.Create(FileChain)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 64; i++ {
		_, _ = w.Write(zeros)
	}
	_ = zw.Close()
	res := run(t, bomb.Bytes(), Options{Limits: Limits{MaxEntries: 16, MaxEntryBytes: 32 << 20, MaxTotalBytes: 32 << 20,
		MaxMetadataBytes: 1 << 20, MaxLineBytes: 1 << 20, MaxRatio: 100}})
	if res.Valid || !codes(res)[verify.CodePackageMalformed] {
		t.Fatalf("zip bomb must be rejected: %v", res.Failures)
	}
}

func TestUnanchoredAndInconsistentPackages(t *testing.T) {
	s := defaultSpec(t)
	s.checkpoints = s.checkpoints[1:] // drop the anchor checkpoint
	res := run(t, build(t, s), Options{})
	if res.Valid || !codes(res)[verify.CodePackageUnanchored] {
		t.Fatalf("expected an unanchored package: %v", res.Failures)
	}

	// A tampered anchor checkpoint is not trusted.
	s = defaultSpec(t)
	s.checkpoints[0].HeadHash[0] ^= 1
	res = run(t, build(t, s), Options{})
	if res.Valid || !codes(res)[verify.CodeCheckpointInvalid] {
		t.Fatalf("expected an invalid anchor checkpoint: %v", res.Failures)
	}

	// Replacing a disclosed event after export breaks the file digest.
	s = defaultSpec(t)
	other := chain(t, newSigner(t), 50)
	s.filter = nil
	data := build(t, s)
	swapped := rewrite(t, data, func(name string, c []byte) ([]byte, bool) {
		if name != FileEvents {
			return c, true
		}
		lines := bytes.Split(bytes.TrimSpace(c), []byte("\n"))
		replacement, _ := json.Marshal(other[24])
		lines[0] = replacement
		return append(bytes.Join(lines, []byte("\n")), '\n'), true
	})
	res = run(t, swapped, Options{})
	if res.Valid || !codes(res)[verify.CodePackageDigestMismatch] {
		t.Fatalf("swapped disclosure must fail: %v", res.Failures)
	}
}

// A producer that signs a manifest over inconsistent files is still caught:
// disclosed content must match the payload hash in the skeleton, and the
// disclosed header must equal the skeleton header.
func TestInconsistentDisclosures(t *testing.T) {
	s := defaultSpec(t)
	s.mutateEvent = func(r integrity.Record) integrity.Record {
		if r.Sequence == 30 {
			r.Content = []byte(`{"action":"contract.updated","actor":{"id":"user_0","type":"user"},"data":{"n":999}}`)
		}
		return r
	}
	res := run(t, build(t, s), Options{TrustedKeys: trusted(t, s.signer)})
	if res.Valid || res.FirstFailure.Code != verify.CodePayloadHashMismatch || res.FirstFailure.Sequence != 30 {
		t.Fatalf("altered content must fail its payload hash: %v", res.Failures)
	}

	s = defaultSpec(t)
	s.mutateEvent = func(r integrity.Record) integrity.Record {
		if r.Sequence == 33 {
			r.Content = []byte(`{"action":"contract.updated","actor":{"id":"user_0","type":"user"},"data":{"n":999}}`)
			r.PayloadHash = integrity.PayloadHash(r.Content)
		}
		return r
	}
	res = run(t, build(t, s), Options{TrustedKeys: trusted(t, s.signer)})
	if res.Valid || res.FirstFailure.Code != verify.CodeDisclosureMismatch || res.FirstFailure.Sequence != 33 {
		t.Fatalf("a disclosed header that differs from the skeleton must fail: %v", res.Failures)
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Verify(bytes.NewReader(data), int64(len(data)), Options{})
		if err == nil && res.Valid {
			t.Fatal("random bytes must never verify")
		}
	})
}
