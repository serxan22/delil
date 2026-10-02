package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/pkg/integrity"
)

// Checkpoint is a stored signed checkpoint.
type Checkpoint struct {
	ID             string
	TenantID       string
	ProjectID      string
	StreamID       string
	StreamName     string
	Sequence       int64
	HeadHash       []byte
	CreatedAt      time.Time
	CheckpointHash []byte
	SigningKeyID   string
	Signature      []byte
}

// Integrity converts the row into the signed checkpoint structure.
func (c *Checkpoint) Integrity() integrity.Checkpoint {
	return integrity.Checkpoint{
		SchemaVersion:  integrity.SchemaVersion,
		CheckpointID:   c.ID,
		TenantID:       c.TenantID,
		ProjectID:      c.ProjectID,
		Stream:         c.StreamName,
		Sequence:       c.Sequence,
		HeadHash:       hashOrZero(c.HeadHash),
		CreatedAt:      integrity.FormatTime(c.CreatedAt),
		KeyID:          c.SigningKeyID,
		CheckpointHash: hashOrZero(c.CheckpointHash),
		Signature:      append([]byte(nil), c.Signature...),
	}
}

const checkpointColumns = `c.id, c.tenant_id, c.project_id, c.stream_id, s.name, c.sequence, c.head_hash, c.created_at,
	c.checkpoint_hash, c.signing_key_id, c.signature`

const checkpointFrom = ` FROM checkpoints c JOIN audit_streams s ON s.id = c.stream_id `

func scanCheckpoint(row interface{ Scan(...any) error }) (Checkpoint, error) {
	var c Checkpoint
	err := row.Scan(&c.ID, &c.TenantID, &c.ProjectID, &c.StreamID, &c.StreamName, &c.Sequence, &c.HeadHash,
		&c.CreatedAt, &c.CheckpointHash, &c.SigningKeyID, &c.Signature)
	return c, mapErr(err)
}

func collectCheckpoints(rows pgx.Rows) ([]Checkpoint, error) {
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		c, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertCheckpoint stores a checkpoint and advances the stream's checkpoint
// position. It returns ErrConflict if a checkpoint already exists at that
// sequence.
func (s *Store) InsertCheckpoint(ctx context.Context, c Checkpoint) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO checkpoints (id, tenant_id, project_id, stream_id, sequence, head_hash,
			created_at, checkpoint_hash, signing_key_id, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			c.ID, c.TenantID, c.ProjectID, c.StreamID, c.Sequence, c.HeadHash, c.CreatedAt, c.CheckpointHash,
			c.SigningKeyID, c.Signature)
		if err != nil {
			return mapErr(err)
		}
		_, err = tx.Exec(ctx, `UPDATE audit_streams SET last_checkpoint_sequence = $2
			WHERE id = $1 AND last_checkpoint_sequence < $2`, c.StreamID, c.Sequence)
		return err
	})
}

// ListCheckpoints returns a stream's checkpoints in ascending sequence order.
func (s *Store) ListCheckpoints(ctx context.Context, tenantID, projectID, streamID string) ([]Checkpoint, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+checkpointColumns+checkpointFrom+`
		WHERE c.tenant_id = $1 AND c.project_id = $2 AND c.stream_id = $3 ORDER BY c.sequence`,
		tenantID, projectID, streamID)
	if err != nil {
		return nil, err
	}
	return collectCheckpoints(rows)
}

// GetCheckpoint returns a checkpoint of the project.
func (s *Store) GetCheckpoint(ctx context.Context, tenantID, projectID, checkpointID string) (Checkpoint, error) {
	return scanCheckpoint(s.Pool.QueryRow(ctx, `SELECT `+checkpointColumns+checkpointFrom+`
		WHERE c.tenant_id = $1 AND c.project_id = $2 AND c.id = $3`, tenantID, projectID, checkpointID))
}

// LatestCheckpointAtOrBefore returns the newest checkpoint with sequence <= seq.
func (s *Store) LatestCheckpointAtOrBefore(ctx context.Context, tenantID, projectID, streamID string, seq int64) (Checkpoint, error) {
	return scanCheckpoint(s.Pool.QueryRow(ctx, `SELECT `+checkpointColumns+checkpointFrom+`
		WHERE c.tenant_id = $1 AND c.project_id = $2 AND c.stream_id = $3 AND c.sequence <= $4
		ORDER BY c.sequence DESC LIMIT 1`, tenantID, projectID, streamID, seq))
}

// CheckpointsInRange returns checkpoints with from <= sequence <= to.
func (s *Store) CheckpointsInRange(ctx context.Context, tenantID, projectID, streamID string, from, to int64) ([]Checkpoint, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+checkpointColumns+checkpointFrom+`
		WHERE c.tenant_id = $1 AND c.project_id = $2 AND c.stream_id = $3 AND c.sequence BETWEEN $4 AND $5
		ORDER BY c.sequence`, tenantID, projectID, streamID, from, to)
	if err != nil {
		return nil, err
	}
	return collectCheckpoints(rows)
}

// StreamsNeedingCheckpoint returns streams with at least minEvents events
// since their last checkpoint, or with any new events whose head is older
// than maxAge.
func (s *Store) StreamsNeedingCheckpoint(ctx context.Context, minEvents int64, maxAge time.Duration, now time.Time, limit int) ([]Stream, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+streamColumns+` FROM audit_streams s
		WHERE s.head_sequence > s.last_checkpoint_sequence
		  AND (s.head_sequence - s.last_checkpoint_sequence >= $1 OR s.head_recorded_at <= $2)
		ORDER BY s.head_sequence - s.last_checkpoint_sequence DESC LIMIT $3`,
		minEvents, now.Add(-maxAge), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stream
	for rows.Next() {
		st, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// InsertCheckpointAnchor records the outcome of publishing a checkpoint.
func (s *Store) InsertCheckpointAnchor(ctx context.Context, id, checkpointID, provider, status string, receipt json.RawMessage, errMsg string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO checkpoint_anchors (id, checkpoint_id, provider, status, receipt, error)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))`, id, checkpointID, provider, status, receipt, errMsg)
	return err
}
