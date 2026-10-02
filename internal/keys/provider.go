// Package keys manages project signing keys: generation, storage of private
// material through pluggable providers, rotation, revocation and the signer
// cache used by the appender.
//
// Providers implemented in v0.1:
//
//   - local: the Ed25519 seed is wrapped with AES-256-GCM under a key derived
//     (HKDF-SHA256) from DELIL_MASTER_KEY and stored in signing_keys. The
//     ciphertext is bound to its key id and project with additional
//     authenticated data, so wrapped keys cannot be swapped between rows.
//   - file: PKCS#8 PEM files in a directory, for operators who mount secrets
//     as files.
//
// KMS, HSM and remote-signer providers implement the same interface; nothing
// in the data model assumes that private material is available locally.
package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

// Generated is the outcome of creating a key: its public half and whatever
// the provider needs persisted to use it later.
type Generated struct {
	PublicKey         ed25519.PublicKey
	ProviderRef       string
	WrappedPrivateKey []byte
}

// Provider creates keys and loads signers for persisted keys.
type Provider interface {
	Name() string
	Generate(ctx context.Context, tenantID, projectID string) (Generated, error)
	Signer(ctx context.Context, key store.SigningKey) (integrity.Signer, error)
}

// ---------------------------------------------------------------------------
// local provider

// MasterKeySize is the required size of DELIL_MASTER_KEY.
const MasterKeySize = 32

const wrapVersion = 1

// LocalProvider wraps private keys with a key derived from the master key.
type LocalProvider struct {
	aead cipher.AEAD
}

// NewLocalProvider derives the wrapping key from a 32-byte master key.
func NewLocalProvider(masterKey []byte) (*LocalProvider, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("keys: master key must be %d bytes, got %d", MasterKeySize, len(masterKey))
	}
	wrapKey, err := hkdf.Key(sha256.New, masterKey, nil, "delil:v1:signing-key-wrap", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &LocalProvider{aead: aead}, nil
}

// Name implements Provider.
func (p *LocalProvider) Name() string { return "local" }

func wrapAAD(keyID, tenantID, projectID string) []byte {
	return []byte("delil:v1:signing-key|" + keyID + "|" + tenantID + "|" + projectID)
}

// Generate implements Provider.
func (p *LocalProvider) Generate(_ context.Context, tenantID, projectID string) (Generated, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, err
	}
	seed := priv.Seed()
	defer clear(seed)
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Generated{}, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(seed)+p.aead.Overhead())
	out = append(out, wrapVersion)
	out = append(out, nonce...)
	out = p.aead.Seal(out, nonce, seed, wrapAAD(integrity.KeyIDFor(pub), tenantID, projectID))
	return Generated{PublicKey: pub, WrappedPrivateKey: out}, nil
}

// Signer implements Provider.
func (p *LocalProvider) Signer(_ context.Context, key store.SigningKey) (integrity.Signer, error) {
	w := key.WrappedPrivateKey
	ns := p.aead.NonceSize()
	if len(w) < 1+ns+p.aead.Overhead() || w[0] != wrapVersion {
		return nil, fmt.Errorf("keys: key %s has no usable wrapped material", key.ID)
	}
	seed, err := p.aead.Open(nil, w[1:1+ns], w[1+ns:], wrapAAD(key.ID, key.TenantID, key.ProjectID))
	if err != nil {
		return nil, fmt.Errorf("keys: cannot unwrap key %s (wrong master key or tampered material)", key.ID)
	}
	defer clear(seed)
	return checkedSigner(ed25519.NewKeyFromSeed(seed), key)
}

func checkedSigner(priv ed25519.PrivateKey, key store.SigningKey) (integrity.Signer, error) {
	signer, err := integrity.NewEd25519Signer(priv)
	if err != nil {
		return nil, err
	}
	if signer.KeyID() != key.ID || string(signer.PublicKey()) != string(key.PublicKey) {
		return nil, fmt.Errorf("keys: private material does not match public key %s", key.ID)
	}
	return signer, nil
}

// ---------------------------------------------------------------------------
// file provider

var refPattern = regexp.MustCompile(`^[0-9a-f]{64}\.pem$`)

// FileProvider stores private keys as PKCS#8 PEM files.
type FileProvider struct {
	dir string
}

// NewFileProvider uses dir, creating it with 0700 permissions if needed.
func NewFileProvider(dir string) (*FileProvider, error) {
	if dir == "" {
		return nil, errors.New("keys: file provider requires a key directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileProvider{dir: dir}, nil
}

// Name implements Provider.
func (p *FileProvider) Name() string { return "file" }

// Generate implements Provider.
func (p *FileProvider) Generate(_ context.Context, _, _ string) (Generated, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Generated{}, err
	}
	ref := integrity.Fingerprint(pub) + ".pem"
	tmp, err := os.CreateTemp(p.dir, ".tmp-*.pem")
	if err != nil {
		return Generated{}, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Generated{}, err
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		tmp.Close()
		return Generated{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Generated{}, err
	}
	if err := tmp.Close(); err != nil {
		return Generated{}, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(p.dir, ref)); err != nil {
		return Generated{}, err
	}
	return Generated{PublicKey: pub, ProviderRef: ref}, nil
}

// Signer implements Provider.
func (p *FileProvider) Signer(_ context.Context, key store.SigningKey) (integrity.Signer, error) {
	// The reference comes from the database; never let it escape the directory.
	if !refPattern.MatchString(key.ProviderRef) {
		return nil, fmt.Errorf("keys: invalid file reference for key %s", key.ID)
	}
	raw, err := os.ReadFile(filepath.Join(p.dir, key.ProviderRef))
	if err != nil {
		return nil, fmt.Errorf("keys: read key file for %s: %w", key.ID, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keys: key file for %s is not a PKCS#8 PEM block", key.ID)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse key file for %s: %w", key.ID, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: key file for %s is not an Ed25519 key", key.ID)
	}
	return checkedSigner(priv, key)
}
