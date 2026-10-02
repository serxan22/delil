package integrity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// AlgorithmEd25519 is the only signature algorithm of schema version 1.
const AlgorithmEd25519 = "Ed25519"

// Key statuses.
const (
	KeyStatusActive  = "active"
	KeyStatusRetired = "retired"
	KeyStatusRevoked = "revoked"
)

// Fingerprint returns the lowercase hex SHA-256 of a raw 32-byte public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// KeyIDFor derives the key identifier from a public key: "ed25519:" followed
// by the first 32 hex characters (128 bits) of its fingerprint. Because the
// identifier is derived, a verifier can always check that a key matches the
// identifier recorded in an event.
func KeyIDFor(pub ed25519.PublicKey) string {
	return "ed25519:" + Fingerprint(pub)[:32]
}

// PublicKey is the public half of a signing key together with the metadata a
// verifier needs. Timestamps use TimeLayout; empty means "not set".
type PublicKey struct {
	KeyID       string `json:"keyId"`
	Algorithm   string `json:"algorithm"`
	PublicKey   []byte `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	TenantID    string `json:"tenantId,omitempty"`
	ProjectID   string `json:"projectId,omitempty"`
	Status      string `json:"status,omitempty"`
	ActivatedAt string `json:"activatedAt,omitempty"`
	RetiredAt   string `json:"retiredAt,omitempty"`
	RevokedAt   string `json:"revokedAt,omitempty"`
}

// NewPublicKey builds a PublicKey with derived identifier and fingerprint.
func NewPublicKey(pub ed25519.PublicKey) PublicKey {
	return PublicKey{
		KeyID:       KeyIDFor(pub),
		Algorithm:   AlgorithmEd25519,
		PublicKey:   append([]byte(nil), pub...),
		Fingerprint: Fingerprint(pub),
	}
}

// Validate checks the algorithm, the key length and that the identifier and
// fingerprint are the ones derived from the key material.
func (k *PublicKey) Validate() error {
	if k.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("integrity: key %s: unsupported algorithm %q", k.KeyID, k.Algorithm)
	}
	if len(k.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("integrity: key %s: public key must be %d bytes", k.KeyID, ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(k.PublicKey)
	if derived := KeyIDFor(pub); k.KeyID != derived {
		return fmt.Errorf("integrity: key id %q does not match its public key (expected %s)", k.KeyID, derived)
	}
	if k.Fingerprint != "" && k.Fingerprint != Fingerprint(pub) {
		return fmt.Errorf("integrity: key %s: fingerprint does not match its public key", k.KeyID)
	}
	for _, ts := range []string{k.ActivatedAt, k.RetiredAt, k.RevokedAt} {
		if ts == "" {
			continue
		}
		if _, err := ParseTime(ts); err != nil {
			return fmt.Errorf("integrity: key %s: %w", k.KeyID, err)
		}
	}
	return nil
}

// Ed25519 returns the key as an ed25519.PublicKey.
func (k *PublicKey) Ed25519() ed25519.PublicKey { return ed25519.PublicKey(k.PublicKey) }

// KeyUsage describes whether a key was allowed to sign at a given time.
type KeyUsage int

const (
	// KeyUsageValid: the time falls inside the key's active window.
	KeyUsageValid KeyUsage = iota
	// KeyUsageBeforeActivation: signed before the key was activated.
	KeyUsageBeforeActivation
	// KeyUsageAfterRetirement: signed after the key was retired by rotation.
	KeyUsageAfterRetirement
	// KeyUsageAfterRevocation: signed after the key was revoked.
	KeyUsageAfterRevocation
)

// UsageAt classifies a signature made at t, allowing for clock skew between
// servers. Keys without timestamps are always considered valid.
func (k *PublicKey) UsageAt(t time.Time, skew time.Duration) KeyUsage {
	if k.RevokedAt != "" {
		if revoked, err := ParseTime(k.RevokedAt); err == nil && t.After(revoked.Add(skew)) {
			return KeyUsageAfterRevocation
		}
	}
	if k.ActivatedAt != "" {
		if activated, err := ParseTime(k.ActivatedAt); err == nil && t.Before(activated.Add(-skew)) {
			return KeyUsageBeforeActivation
		}
	}
	if k.RetiredAt != "" {
		if retired, err := ParseTime(k.RetiredAt); err == nil && t.After(retired.Add(skew)) {
			return KeyUsageAfterRetirement
		}
	}
	return KeyUsageValid
}

// KeySet is an immutable set of trusted public keys indexed by key ID.
type KeySet struct {
	keys map[string]PublicKey
}

// NewKeySet validates the keys and builds a set. Supplying two different keys
// with the same identifier is an error.
func NewKeySet(keys ...PublicKey) (*KeySet, error) {
	s := &KeySet{keys: make(map[string]PublicKey, len(keys))}
	for _, k := range keys {
		if err := k.Validate(); err != nil {
			return nil, err
		}
		if existing, ok := s.keys[k.KeyID]; ok {
			if string(existing.PublicKey) != string(k.PublicKey) {
				return nil, fmt.Errorf("integrity: conflicting keys for id %s", k.KeyID)
			}
			continue
		}
		s.keys[k.KeyID] = k
	}
	return s, nil
}

// Get returns the key with the given identifier.
func (s *KeySet) Get(keyID string) (PublicKey, bool) {
	if s == nil {
		return PublicKey{}, false
	}
	k, ok := s.keys[keyID]
	return k, ok
}

// Len returns the number of keys in the set.
func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

// Keys returns the keys sorted by identifier.
func (s *KeySet) Keys() []PublicKey {
	if s == nil {
		return nil
	}
	out := make([]PublicKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// Signer produces Ed25519 signatures. Implementations may keep the private key
// in memory, in a file, in a cloud KMS or in an HSM; callers only ever see the
// public key.
type Signer interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// Ed25519Signer signs with an in-memory private key.
type Ed25519Signer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// NewEd25519Signer wraps a private key.
func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("integrity: invalid Ed25519 private key length")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{priv: priv, pub: pub, keyID: KeyIDFor(pub)}, nil
}

// NewEd25519SignerFromSeed derives a signer from a 32-byte RFC 8032 seed.
func NewEd25519SignerFromSeed(seed []byte) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("integrity: Ed25519 seed must be 32 bytes")
	}
	return NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
}

// KeyID implements Signer.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// PublicKey implements Signer.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Sign implements Signer.
func (s *Ed25519Signer) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// VerifySignature checks an Ed25519 signature over tag || 0x00 || h. Go's
// implementation rejects non-canonical scalars, so signatures are not
// malleable.
func VerifySignature(pub ed25519.PublicKey, tag string, h Hash, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, SigningMessage(tag, h), sig)
}
