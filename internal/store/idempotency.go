package store

import (
	"context"
	"time"
)

// IdempotencyRecord remembers the outcome of an ingestion request.
type IdempotencyRecord struct {
	ProjectID   string
	Key         string
	Endpoint    string
	RequestHash []byte
	EventIDs    []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// GetIdempotency returns a live record.
func (s *Store) GetIdempotency(ctx context.Context, db DBTX, projectID, key string, now time.Time) (IdempotencyRecord, error) {
	var r IdempotencyRecord
	err := db.QueryRow(ctx, `SELECT project_id, key, endpoint, request_hash, event_ids, created_at, expires_at
		FROM idempotency_keys WHERE project_id = $1 AND key = $2 AND expires_at > $3`, projectID, key, now).
		Scan(&r.ProjectID, &r.Key, &r.Endpoint, &r.RequestHash, &r.EventIDs, &r.CreatedAt, &r.ExpiresAt)
	return r, mapErr(err)
}

// InsertIdempotency records a key inside the append transaction. It returns
// false if a live record already exists (a concurrent request committed
// first). An expired record with the same key is replaced.
func (s *Store) InsertIdempotency(ctx context.Context, db DBTX, r IdempotencyRecord) (bool, error) {
	tag, err := db.Exec(ctx, `INSERT INTO idempotency_keys (project_id, key, endpoint, request_hash, event_ids,
		created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (project_id, key) DO UPDATE SET endpoint = EXCLUDED.endpoint, request_hash = EXCLUDED.request_hash,
			event_ids = EXCLUDED.event_ids, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at
		WHERE idempotency_keys.expires_at <= EXCLUDED.created_at`,
		r.ProjectID, r.Key, r.Endpoint, r.RequestHash, r.EventIDs, r.CreatedAt, r.ExpiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredIdempotency removes expired records.
func (s *Store) DeleteExpiredIdempotency(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at <= $1`, now)
	return tag.RowsAffected(), err
}
