package store

import (
	"context"
	"encoding/json"
	"time"
)

// Export is an evidence-package job.
type Export struct {
	ID                string
	TenantID          string
	ProjectID         string
	StreamID          string
	StreamName        string
	Status            string
	Params            json.RawMessage
	CreatedBy         string
	CreatedAt         time.Time
	StartedAt         *time.Time
	CompletedAt       *time.Time
	ExpiresAt         *time.Time
	Attempts          int
	ChainEvents       *int64
	DisclosedEvents   *int64
	FirstSequence     *int64
	LastSequence      *int64
	SizeBytes         *int64
	SHA256            []byte
	ManifestHash      []byte
	StoragePath       string
	VerificationValid *bool
	Error             string
}

const exportColumns = `x.id, x.tenant_id, x.project_id, x.stream_id, s.name, x.status, x.params, COALESCE(x.created_by, ''),
	x.created_at, x.started_at, x.completed_at, x.expires_at, x.attempts, x.chain_events, x.disclosed_events,
	x.first_sequence, x.last_sequence, x.size_bytes, x.sha256, x.manifest_hash, COALESCE(x.storage_path, ''),
	x.verification_valid, COALESCE(x.error, '')`

const exportFrom = ` FROM exports x JOIN audit_streams s ON s.id = x.stream_id `

func scanExport(row interface{ Scan(...any) error }) (Export, error) {
	var x Export
	err := row.Scan(&x.ID, &x.TenantID, &x.ProjectID, &x.StreamID, &x.StreamName, &x.Status, &x.Params, &x.CreatedBy,
		&x.CreatedAt, &x.StartedAt, &x.CompletedAt, &x.ExpiresAt, &x.Attempts, &x.ChainEvents, &x.DisclosedEvents,
		&x.FirstSequence, &x.LastSequence, &x.SizeBytes, &x.SHA256, &x.ManifestHash, &x.StoragePath,
		&x.VerificationValid, &x.Error)
	return x, mapErr(err)
}

// CreateExport inserts a pending export.
func (s *Store) CreateExport(ctx context.Context, x Export) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO exports (id, tenant_id, project_id, stream_id, status, params, created_by,
		created_at) VALUES ($1, $2, $3, $4, 'pending', $5, NULLIF($6, ''), $7)`,
		x.ID, x.TenantID, x.ProjectID, x.StreamID, x.Params, x.CreatedBy, x.CreatedAt)
	return mapErr(err)
}

// GetExport returns an export of the project.
func (s *Store) GetExport(ctx context.Context, tenantID, projectID, exportID string) (Export, error) {
	return scanExport(s.Pool.QueryRow(ctx, `SELECT `+exportColumns+exportFrom+`
		WHERE x.tenant_id = $1 AND x.project_id = $2 AND x.id = $3`, tenantID, projectID, exportID))
}

// ListExports returns the newest exports of the project.
func (s *Store) ListExports(ctx context.Context, tenantID, projectID string, limit int) ([]Export, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+exportColumns+exportFrom+`
		WHERE x.tenant_id = $1 AND x.project_id = $2 ORDER BY x.created_at DESC LIMIT $3`, tenantID, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Export
	for rows.Next() {
		x, err := scanExport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ClaimExport atomically takes the oldest pending export, or a running one
// whose lease expired (its worker died), and leases it.
func (s *Store) ClaimExport(ctx context.Context, now time.Time, lease time.Duration, maxAttempts int) (Export, error) {
	return scanExport(s.Pool.QueryRow(ctx, `WITH claimed AS (
			UPDATE exports SET status = 'running', started_at = COALESCE(started_at, $1), lease_until = $2,
			       attempts = attempts + 1
			 WHERE id = (SELECT id FROM exports
			              WHERE (status = 'pending' OR (status = 'running' AND lease_until < $1)) AND attempts < $3
			              ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
			RETURNING *)
		SELECT `+exportColumns+` FROM claimed x JOIN audit_streams s ON s.id = x.stream_id`,
		now, now.Add(lease), maxAttempts))
}

// CompleteExport marks an export as completed.
func (s *Store) CompleteExport(ctx context.Context, x Export) error {
	_, err := s.Pool.Exec(ctx, `UPDATE exports SET status = 'completed', completed_at = $2, expires_at = $3,
		chain_events = $4, disclosed_events = $5, first_sequence = $6, last_sequence = $7, size_bytes = $8, sha256 = $9,
		manifest_hash = $10, storage_path = $11, verification_valid = $12, lease_until = NULL, error = NULL
		WHERE id = $1`,
		x.ID, x.CompletedAt, x.ExpiresAt, x.ChainEvents, x.DisclosedEvents, x.FirstSequence, x.LastSequence,
		x.SizeBytes, x.SHA256, x.ManifestHash, x.StoragePath, x.VerificationValid)
	return err
}

// FailExport records a failed attempt. The export returns to "pending" while
// attempts remain, otherwise it is marked failed.
func (s *Store) FailExport(ctx context.Context, exportID, msg string, maxAttempts int, now time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE exports SET
		status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END,
		completed_at = CASE WHEN attempts >= $3 THEN $4::timestamptz ELSE NULL END,
		lease_until = NULL, error = $2 WHERE id = $1`, exportID, msg, maxAttempts, now)
	return err
}

// ExpireExports marks completed exports past their expiry as expired and
// returns them so their files can be deleted.
func (s *Store) ExpireExports(ctx context.Context, now time.Time) ([]Export, error) {
	rows, err := s.Pool.Query(ctx, `WITH expired AS (
			UPDATE exports SET status = 'expired' WHERE status = 'completed' AND expires_at < $1 RETURNING *)
		SELECT `+exportColumns+` FROM expired x JOIN audit_streams s ON s.id = x.stream_id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Export
	for rows.Next() {
		x, err := scanExport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
