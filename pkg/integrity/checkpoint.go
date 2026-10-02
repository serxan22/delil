package integrity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/serxan22/delil/pkg/jcs"
)

// Checkpoint is a signed statement that a stream's head was HeadHash at
// Sequence when the checkpoint was created. Checkpoints can be stored outside
// DƏLİL (witnessing) or anchored with external services; a chain that no
// longer contains a checkpointed head has been rolled back or forked.
type Checkpoint struct {
	SchemaVersion  int       `json:"schemaVersion"`
	CheckpointID   string    `json:"checkpointId"`
	TenantID       string    `json:"tenantId"`
	ProjectID      string    `json:"projectId"`
	Stream         string    `json:"stream"`
	Sequence       int64     `json:"sequence"`
	HeadHash       Hash      `json:"headHash"`
	CreatedAt      string    `json:"createdAt"`
	KeyID          string    `json:"keyId"`
	CheckpointHash Hash      `json:"checkpointHash"`
	Signature      Signature `json:"signature"`
}

// Canonical returns the canonical encoding of the signed checkpoint body
// (every field except checkpointHash and signature).
func (c *Checkpoint) Canonical() ([]byte, error) {
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("integrity: unsupported checkpoint schema version %d", c.SchemaVersion)
	}
	if c.Sequence < 1 {
		return nil, errors.New("integrity: checkpoint sequence must be positive")
	}
	if !ValidStreamName(c.Stream) {
		return nil, fmt.Errorf("integrity: invalid stream name %q", c.Stream)
	}
	if _, err := ParseTime(c.CreatedAt); err != nil {
		return nil, err
	}
	return jcs.Marshal(map[string]any{
		"schemaVersion": c.SchemaVersion,
		"checkpointId":  c.CheckpointID,
		"tenantId":      c.TenantID,
		"projectId":     c.ProjectID,
		"stream":        c.Stream,
		"sequence":      c.Sequence,
		"headHash":      c.HeadHash.String(),
		"createdAt":     c.CreatedAt,
		"keyId":         c.KeyID,
	})
}

// ComputeHash returns the checkpoint hash of the body.
func (c *Checkpoint) ComputeHash() (Hash, error) {
	canonical, err := c.Canonical()
	if err != nil {
		return Hash{}, err
	}
	return TaggedHash(TagCheckpoint, canonical), nil
}

// NewCheckpoint builds and signs a checkpoint.
func NewCheckpoint(ctx context.Context, signer Signer, id, tenantID, projectID, stream string,
	sequence int64, head Hash, createdAt time.Time) (Checkpoint, error) {
	c := Checkpoint{
		SchemaVersion: SchemaVersion,
		CheckpointID:  id,
		TenantID:      tenantID,
		ProjectID:     projectID,
		Stream:        stream,
		Sequence:      sequence,
		HeadHash:      head,
		CreatedAt:     FormatTime(createdAt),
		KeyID:         signer.KeyID(),
	}
	h, err := c.ComputeHash()
	if err != nil {
		return Checkpoint{}, err
	}
	sig, err := signer.Sign(ctx, SigningMessage(TagCheckpointSignature, h))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("integrity: signing checkpoint: %w", err)
	}
	if !VerifySignature(signer.PublicKey(), TagCheckpointSignature, h, sig) {
		return Checkpoint{}, errors.New("integrity: signer produced a checkpoint signature that does not verify")
	}
	c.CheckpointHash = h
	c.Signature = sig
	return c, nil
}

// Checkpoint verification errors.
var (
	ErrCheckpointHash       = errors.New("checkpoint hash does not match its contents")
	ErrCheckpointUnknownKey = errors.New("checkpoint is signed by a key that is not trusted")
	ErrCheckpointSignature  = errors.New("checkpoint signature is invalid")
)

// Verify recomputes the checkpoint hash and checks the signature against the
// trusted key set.
func (c *Checkpoint) Verify(keys *KeySet) error {
	h, err := c.ComputeHash()
	if err != nil {
		return err
	}
	if !h.Equal(c.CheckpointHash) {
		return ErrCheckpointHash
	}
	key, ok := keys.Get(c.KeyID)
	if !ok {
		return ErrCheckpointUnknownKey
	}
	if !VerifySignature(key.Ed25519(), TagCheckpointSignature, h, c.Signature) {
		return ErrCheckpointSignature
	}
	return nil
}
