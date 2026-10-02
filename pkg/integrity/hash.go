// Package integrity defines DƏLİL's integrity model, schema version 1: the
// event header and chain record formats, domain-separated hashing, signing
// messages, key identifiers and checkpoints.
//
// The construction (see docs/cryptographic-model.md):
//
//	payloadHash    = SHA-256("delil:v1:payload"    || 0x00 || JCS(content))
//	eventHash      = SHA-256("delil:v1:event"      || 0x00 || JCS(header))
//	signature      = Ed25519(sk, "delil:v1:event-signature" || 0x00 || eventHash)
//	checkpointHash = SHA-256("delil:v1:checkpoint" || 0x00 || JCS(checkpoint body))
//
// Every function in this package is deterministic and free of I/O so that
// verifiers can be audited and reimplemented independently. Known-answer test
// vectors are published in docs/test-vectors.json.
package integrity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// SchemaVersion is the integrity schema implemented by this package.
const SchemaVersion = 1

// Domain-separation tags. Each is followed by a single 0x00 byte, which never
// occurs inside a tag and never occurs unescaped in canonical JSON, so the
// encoding of (tag, data) is unambiguous.
const (
	TagPayload             = "delil:v1:payload"
	TagEvent               = "delil:v1:event"
	TagEventSignature      = "delil:v1:event-signature"
	TagCheckpoint          = "delil:v1:checkpoint"
	TagCheckpointSignature = "delil:v1:checkpoint-signature"
	TagManifest            = "delil:v1:manifest"
	TagManifestSignature   = "delil:v1:manifest-signature"
)

// HashSize is the size of a SHA-256 digest in bytes.
const HashSize = sha256.Size

// Hash is a SHA-256 digest. Its text form is 64 lowercase hexadecimal
// characters.
type Hash [HashSize]byte

// ZeroHash is the previousHash of the first event in every stream.
var ZeroHash Hash

// String returns the lowercase hexadecimal form of h.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// IsZero reports whether h is the all-zero genesis value.
func (h Hash) IsZero() bool { return h == ZeroHash }

// Equal compares two hashes in constant time.
func (h Hash) Equal(other Hash) bool {
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

// Short returns the first 12 hexadecimal characters, for display only.
func (h Hash) Short() string { return h.String()[:12] }

// MarshalText implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(HashSize))
	hex.Encode(out, h[:])
	return out, nil
}

// UnmarshalText implements encoding.TextUnmarshaler. Only the canonical
// lowercase form is accepted.
func (h *Hash) UnmarshalText(text []byte) error {
	parsed, err := ParseHash(string(text))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

// ParseHash parses the canonical 64-character lowercase hexadecimal form.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != hex.EncodedLen(HashSize) {
		return h, fmt.Errorf("integrity: hash must be %d hex characters, got %d", hex.EncodedLen(HashSize), len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return h, fmt.Errorf("integrity: hash must be lowercase hexadecimal")
		}
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, fmt.Errorf("integrity: invalid hash: %w", err)
	}
	return h, nil
}

// HashFromBytes converts a 32-byte slice into a Hash.
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	if len(b) != HashSize {
		return h, fmt.Errorf("integrity: hash must be %d bytes, got %d", HashSize, len(b))
	}
	copy(h[:], b)
	return h, nil
}

// TaggedHash computes SHA-256(tag || 0x00 || data).
func TaggedHash(tag string, data []byte) Hash {
	d := sha256.New()
	d.Write([]byte(tag))
	d.Write([]byte{0})
	d.Write(data)
	var h Hash
	d.Sum(h[:0])
	return h
}

// SigningMessage returns tag || 0x00 || h, the exact bytes passed to Ed25519.
func SigningMessage(tag string, h Hash) []byte {
	msg := make([]byte, 0, len(tag)+1+HashSize)
	msg = append(msg, tag...)
	msg = append(msg, 0)
	return append(msg, h[:]...)
}

// PayloadHash hashes canonical event content. The caller is responsible for
// passing the RFC 8785 canonical form.
func PayloadHash(canonicalContent []byte) Hash {
	return TaggedHash(TagPayload, canonicalContent)
}
