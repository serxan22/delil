package integrity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/serxan22/delil/pkg/jcs"
)

// TimeLayout is the only accepted timestamp format inside hashed structures:
// UTC with exactly six fractional digits. PostgreSQL timestamptz stores
// microseconds, so this form round-trips through the database byte for byte.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// FormatTime renders t in TimeLayout, truncated to microseconds.
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(TimeLayout)
}

// ParseTime parses a timestamp that must already be in canonical TimeLayout
// form.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("integrity: timestamp %q is not in canonical form %s", s, TimeLayout)
	}
	if t.Format(TimeLayout) != s {
		return time.Time{}, fmt.Errorf("integrity: timestamp %q is not in canonical form %s", s, TimeLayout)
	}
	return t, nil
}

// Identifier patterns. They are enforced when headers are built so that every
// value inside a hashed header is printable ASCII.
var (
	idPattern     = regexp.MustCompile(`^[a-z]{2,8}_[0-9A-Za-z]{10,64}$`)
	streamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	keyIDPattern  = regexp.MustCompile(`^ed25519:[0-9a-f]{32}$`)
)

// ValidStreamName reports whether name is an acceptable stream name.
func ValidStreamName(name string) bool { return streamPattern.MatchString(name) }

// Header contains every field covered by an event hash.
type Header struct {
	SchemaVersion int    `json:"schemaVersion"`
	TenantID      string `json:"tenantId"`
	ProjectID     string `json:"projectId"`
	Stream        string `json:"stream"`
	Sequence      int64  `json:"sequence"`
	EventID       string `json:"eventId"`
	RecordedAt    string `json:"recordedAt"`
	PreviousHash  Hash   `json:"previousHash"`
	PayloadHash   Hash   `json:"payloadHash"`
	KeyID         string `json:"keyId"`
}

// Validate checks that h is well-formed. It does not check cryptographic
// properties.
func (h *Header) Validate() error {
	switch {
	case h.SchemaVersion != SchemaVersion:
		return fmt.Errorf("integrity: unsupported schema version %d", h.SchemaVersion)
	case !idPattern.MatchString(h.TenantID):
		return fmt.Errorf("integrity: invalid tenant id %q", h.TenantID)
	case !idPattern.MatchString(h.ProjectID):
		return fmt.Errorf("integrity: invalid project id %q", h.ProjectID)
	case !streamPattern.MatchString(h.Stream):
		return fmt.Errorf("integrity: invalid stream name %q", h.Stream)
	case h.Sequence < 1 || h.Sequence > 1<<53:
		return fmt.Errorf("integrity: sequence %d out of range", h.Sequence)
	case !idPattern.MatchString(h.EventID):
		return fmt.Errorf("integrity: invalid event id %q", h.EventID)
	case !keyIDPattern.MatchString(h.KeyID):
		return fmt.Errorf("integrity: invalid key id %q", h.KeyID)
	}
	if _, err := ParseTime(h.RecordedAt); err != nil {
		return err
	}
	if h.Sequence == 1 && !h.PreviousHash.IsZero() {
		return errors.New("integrity: the first event of a stream must have the zero previous hash")
	}
	return nil
}

// Canonical returns the RFC 8785 canonical encoding of the header.
func (h *Header) Canonical() ([]byte, error) {
	return jcs.Marshal(map[string]any{
		"schemaVersion": h.SchemaVersion,
		"tenantId":      h.TenantID,
		"projectId":     h.ProjectID,
		"stream":        h.Stream,
		"sequence":      h.Sequence,
		"eventId":       h.EventID,
		"recordedAt":    h.RecordedAt,
		"previousHash":  h.PreviousHash.String(),
		"payloadHash":   h.PayloadHash.String(),
		"keyId":         h.KeyID,
	})
}

// Hash computes the event hash of the header.
func (h *Header) Hash() (Hash, error) {
	canonical, err := h.Canonical()
	if err != nil {
		return Hash{}, err
	}
	return TaggedHash(TagEvent, canonical), nil
}

// Signature is an Ed25519 signature. Its text form is standard base64.
type Signature []byte

// MarshalText implements encoding.TextMarshaler.
func (s Signature) MarshalText() ([]byte, error) {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(s)))
	base64.StdEncoding.Encode(out, s)
	return out, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Signature) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.Strict().DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("integrity: invalid signature encoding: %w", err)
	}
	*s = b
	return nil
}

// String returns the base64 form of s.
func (s Signature) String() string { return base64.StdEncoding.EncodeToString(s) }

// Record is a committed event as it appears in the chain: the header, the
// event hash, the signature and, unless withheld, the canonical content.
//
// The same structure is used by the database, the /chain API endpoint and
// evidence packages, so all three are verified by identical code.
type Record struct {
	Header
	EventHash Hash      `json:"eventHash"`
	Signature Signature `json:"signature"`
	// Content is the exact RFC 8785 canonical event content. It is nil for
	// header-only records (selective disclosure).
	Content json.RawMessage `json:"content,omitempty"`
}

// HasContent reports whether the record carries its content.
func (r *Record) HasContent() bool { return len(r.Content) > 0 }

// WithoutContent returns a copy of r with the content removed.
func (r Record) WithoutContent() Record {
	r.Content = nil
	return r
}

// SealInput is what the appender knows before an event is committed.
type SealInput struct {
	TenantID     string
	ProjectID    string
	Stream       string
	Sequence     int64
	EventID      string
	RecordedAt   time.Time
	PreviousHash Hash
	// CanonicalContent must be the RFC 8785 canonical event content.
	CanonicalContent []byte
}

// Seal hashes, links and signs an event, returning the complete record. The
// signature is verified with the signer's public key before returning, so a
// malfunctioning signer can never produce a record that fails verification.
func Seal(ctx context.Context, in SealInput, signer Signer) (Record, error) {
	header := Header{
		SchemaVersion: SchemaVersion,
		TenantID:      in.TenantID,
		ProjectID:     in.ProjectID,
		Stream:        in.Stream,
		Sequence:      in.Sequence,
		EventID:       in.EventID,
		RecordedAt:    FormatTime(in.RecordedAt),
		PreviousHash:  in.PreviousHash,
		PayloadHash:   PayloadHash(in.CanonicalContent),
		KeyID:         signer.KeyID(),
	}
	if err := header.Validate(); err != nil {
		return Record{}, err
	}
	eventHash, err := header.Hash()
	if err != nil {
		return Record{}, err
	}
	sig, err := signer.Sign(ctx, SigningMessage(TagEventSignature, eventHash))
	if err != nil {
		return Record{}, fmt.Errorf("integrity: signing failed: %w", err)
	}
	if !VerifySignature(signer.PublicKey(), TagEventSignature, eventHash, sig) {
		return Record{}, errors.New("integrity: signer produced a signature that does not verify")
	}
	return Record{
		Header:    header,
		EventHash: eventHash,
		Signature: sig,
		Content:   append(json.RawMessage(nil), in.CanonicalContent...),
	}, nil
}
