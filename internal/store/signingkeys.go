package store

import (
	"context"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
)

// SigningKey is a project signing key. WrappedPrivateKey is only populated by
// GetSigningKeyMaterial and is never returned by listing methods.
type SigningKey struct {
	ID                string
	TenantID          string
	ProjectID         string
	Algorithm         string
	PublicKey         []byte
	Fingerprint       string
	Provider          string
	ProviderRef       string
	WrappedPrivateKey []byte
	Status            string
	CreatedAt         time.Time
	ActivatedAt       time.Time
	RetiredAt         *time.Time
	RevokedAt         *time.Time
	RevocationReason  string
	EventCount        int64
}

// Public converts the key into the verifier's representation.
func (k *SigningKey) Public() integrity.PublicKey {
	pk := integrity.PublicKey{
		KeyID:       k.ID,
		Algorithm:   k.Algorithm,
		PublicKey:   append([]byte(nil), k.PublicKey...),
		Fingerprint: k.Fingerprint,
		TenantID:    k.TenantID,
		ProjectID:   k.ProjectID,
		Status:      k.Status,
		ActivatedAt: integrity.FormatTime(k.ActivatedAt),
	}
	if k.RetiredAt != nil {
		pk.RetiredAt = integrity.FormatTime(*k.RetiredAt)
	}
	if k.RevokedAt != nil {
		pk.RevokedAt = integrity.FormatTime(*k.RevokedAt)
	}
	return pk
}

const signingKeyColumns = `id, tenant_id, project_id, algorithm, public_key, fingerprint, provider,
	COALESCE(provider_ref, ''), status, created_at, activated_at, retired_at, revoked_at, COALESCE(revocation_reason, '')`

func scanSigningKey(row interface{ Scan(...any) error }, extra ...any) (SigningKey, error) {
	var k SigningKey
	dest := []any{&k.ID, &k.TenantID, &k.ProjectID, &k.Algorithm, &k.PublicKey, &k.Fingerprint, &k.Provider,
		&k.ProviderRef, &k.Status, &k.CreatedAt, &k.ActivatedAt, &k.RetiredAt, &k.RevokedAt, &k.RevocationReason}
	err := row.Scan(append(dest, extra...)...)
	return k, mapErr(err)
}

// InsertSigningKey stores a new key.
func (s *Store) InsertSigningKey(ctx context.Context, db DBTX, k SigningKey) error {
	_, err := db.Exec(ctx, `INSERT INTO signing_keys (id, tenant_id, project_id, algorithm, public_key, fingerprint,
		provider, provider_ref, wrapped_private_key, status, created_at, activated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11, $12)`,
		k.ID, k.TenantID, k.ProjectID, k.Algorithm, k.PublicKey, k.Fingerprint, k.Provider, k.ProviderRef,
		k.WrappedPrivateKey, k.Status, k.CreatedAt, k.ActivatedAt)
	return mapErr(err)
}

// ActiveSigningKeyForUpdate locks and returns the project's active key.
// Appends take FOR KEY SHARE (see audit.Appender); rotation takes FOR UPDATE,
// so a rotation waits for in-flight appends.
func (s *Store) ActiveSigningKeyForUpdate(ctx context.Context, db DBTX, tenantID, projectID string) (SigningKey, error) {
	return scanSigningKey(db.QueryRow(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys
		WHERE tenant_id = $1 AND project_id = $2 AND status = 'active' FOR UPDATE`, tenantID, projectID))
}

// ActiveSigningKeyShared share-locks and returns the project's active key id.
func (s *Store) ActiveSigningKeyShared(ctx context.Context, db DBTX, tenantID, projectID string) (string, error) {
	var keyID string
	err := db.QueryRow(ctx, `SELECT id FROM signing_keys
		WHERE tenant_id = $1 AND project_id = $2 AND status = 'active' FOR KEY SHARE`, tenantID, projectID).Scan(&keyID)
	return keyID, mapErr(err)
}

// GetActiveSigningKey returns the project's active key without locking.
func (s *Store) GetActiveSigningKey(ctx context.Context, tenantID, projectID string) (SigningKey, error) {
	return scanSigningKey(s.Pool.QueryRow(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys
		WHERE tenant_id = $1 AND project_id = $2 AND status = 'active'`, tenantID, projectID))
}

// GetSigningKeyMaterial returns a key including its wrapped private material.
func (s *Store) GetSigningKeyMaterial(ctx context.Context, keyID string) (SigningKey, error) {
	var wrapped []byte
	k, err := scanSigningKey(s.Pool.QueryRow(ctx, `SELECT `+signingKeyColumns+`, wrapped_private_key
		FROM signing_keys WHERE id = $1`, keyID), &wrapped)
	k.WrappedPrivateKey = wrapped
	return k, err
}

// ListSigningKeys returns the project's keys with the number of events each
// one signed, oldest first.
func (s *Store) ListSigningKeys(ctx context.Context, tenantID, projectID string) ([]SigningKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+signingKeyColumns+`,
		(SELECT count(*) FROM audit_events e WHERE e.signing_key_id = k.id)
		FROM signing_keys k WHERE tenant_id = $1 AND project_id = $2 ORDER BY activated_at, created_at`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var count int64
		k, err := scanSigningKey(rows, &count)
		if err != nil {
			return nil, err
		}
		k.EventCount = count
		out = append(out, k)
	}
	return out, rows.Err()
}

// PublicKeys returns every key of the project in verifier form.
func (s *Store) PublicKeys(ctx context.Context, tenantID, projectID string) ([]integrity.PublicKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys
		WHERE tenant_id = $1 AND project_id = $2 ORDER BY activated_at`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []integrity.PublicKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k.Public())
	}
	return out, rows.Err()
}

// LatestRecordedAtForKey returns the newest recorded_at of events signed by
// the key, used to close its validity window on rotation.
func (s *Store) LatestRecordedAtForKey(ctx context.Context, db DBTX, keyID string) (*time.Time, error) {
	var t *time.Time
	err := db.QueryRow(ctx, `SELECT max(recorded_at) FROM audit_events WHERE signing_key_id = $1`, keyID).Scan(&t)
	return t, err
}

// RetireSigningKey marks an active key as retired.
func (s *Store) RetireSigningKey(ctx context.Context, db DBTX, keyID string, at time.Time) error {
	tag, err := db.Exec(ctx, `UPDATE signing_keys SET status = 'retired', retired_at = $2
		WHERE id = $1 AND status = 'active'`, keyID, at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSigningKey marks a key as revoked.
func (s *Store) RevokeSigningKey(ctx context.Context, db DBTX, tenantID, projectID, keyID, reason string, at time.Time) error {
	tag, err := db.Exec(ctx, `UPDATE signing_keys SET status = 'revoked', revoked_at = $4, revocation_reason = $5,
		retired_at = COALESCE(retired_at, $4)
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND status <> 'revoked'`,
		tenantID, projectID, keyID, at, reason)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
