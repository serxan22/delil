package keys

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

func masterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, MasterKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func record(gen Generated, provider, tenant, project string) store.SigningKey {
	return store.SigningKey{
		ID: integrity.KeyIDFor(gen.PublicKey), TenantID: tenant, ProjectID: project, Algorithm: integrity.AlgorithmEd25519,
		PublicKey: gen.PublicKey, Fingerprint: integrity.Fingerprint(gen.PublicKey), Provider: provider,
		ProviderRef: gen.ProviderRef, WrappedPrivateKey: gen.WrappedPrivateKey,
	}
}

func signAndCheck(t *testing.T, s integrity.Signer, rec store.SigningKey) {
	t.Helper()
	h := integrity.TaggedHash(integrity.TagEvent, []byte("x"))
	sig, err := s.Sign(context.Background(), integrity.SigningMessage(integrity.TagEventSignature, h))
	if err != nil {
		t.Fatal(err)
	}
	if !integrity.VerifySignature(rec.PublicKey, integrity.TagEventSignature, h, sig) {
		t.Fatal("signature does not verify under the recorded public key")
	}
}

func TestLocalProvider(t *testing.T) {
	ctx := context.Background()
	mk := masterKey(t)
	p, err := NewLocalProvider(mk)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := p.Generate(ctx, "org_A", "prj_A")
	if err != nil {
		t.Fatal(err)
	}
	if len(gen.WrappedPrivateKey) == 0 || strings.Contains(string(gen.WrappedPrivateKey), string(gen.PublicKey)) {
		t.Fatal("wrapped material looks wrong")
	}
	rec := record(gen, "local", "org_A", "prj_A")
	s, err := p.Signer(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	signAndCheck(t, s, rec)

	// Another master key cannot unwrap it.
	other, _ := NewLocalProvider(masterKey(t))
	if _, err := other.Signer(ctx, rec); err == nil {
		t.Fatal("a different master key must not unwrap the key")
	}
	// The ciphertext is bound to its project: moving it fails.
	moved := rec
	moved.ProjectID = "prj_B"
	if _, err := p.Signer(ctx, moved); err == nil {
		t.Fatal("wrapped keys must be bound to their project")
	}
	// Swapping material between two key records fails.
	gen2, _ := p.Generate(ctx, "org_A", "prj_A")
	swapped := record(gen2, "local", "org_A", "prj_A")
	swapped.WrappedPrivateKey = gen.WrappedPrivateKey
	if _, err := p.Signer(ctx, swapped); err == nil {
		t.Fatal("wrapped material must be bound to its key id")
	}
	// Flipping a ciphertext bit is detected by GCM.
	tampered := rec
	tampered.WrappedPrivateKey = append([]byte(nil), rec.WrappedPrivateKey...)
	tampered.WrappedPrivateKey[len(tampered.WrappedPrivateKey)-1] ^= 1
	if _, err := p.Signer(ctx, tampered); err == nil {
		t.Fatal("tampered material must be rejected")
	}
	if _, err := NewLocalProvider(make([]byte, 16)); err == nil {
		t.Fatal("short master keys must be rejected")
	}
}

func TestFileProvider(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p, err := NewFileProvider(dir)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := p.Generate(ctx, "org_A", "prj_A")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, gen.ProviderRef))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file permissions are %v, want 0600", info.Mode().Perm())
	}
	rec := record(gen, "file", "org_A", "prj_A")
	s, err := p.Signer(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	signAndCheck(t, s, rec)

	for _, ref := range []string{"../../etc/passwd", "/etc/passwd", "x.pem", strings.Repeat("a", 64) + ".pem.bak"} {
		bad := rec
		bad.ProviderRef = ref
		if _, err := p.Signer(ctx, bad); err == nil {
			t.Errorf("reference %q must be rejected", ref)
		}
	}
	// A file that holds a different key than the record claims is rejected.
	gen2, _ := p.Generate(ctx, "org_A", "prj_A")
	mismatch := rec
	mismatch.ProviderRef = gen2.ProviderRef
	if _, err := p.Signer(ctx, mismatch); err == nil {
		t.Fatal("key material must match the recorded public key")
	}
}
