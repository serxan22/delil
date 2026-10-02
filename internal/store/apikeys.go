package store

import (
	"context"
	"time"
)

// APIKey is a project-scoped machine credential.
type APIKey struct {
	ID         string
	TenantID   string
	ProjectID  string
	Name       string
	LookupID   string
	SecretHash []byte
	Scopes     []string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
}

//nolint:gosec // a column list, not a credential
const apiKeyColumns = `id, tenant_id, project_id, name, lookup_id, secret_hash, scopes, COALESCE(created_by, ''),
	created_at, last_used_at, expires_at, revoked_at`

func scanAPIKey(row interface{ Scan(...any) error }) (APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.TenantID, &k.ProjectID, &k.Name, &k.LookupID, &k.SecretHash, &k.Scopes, &k.CreatedBy,
		&k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt)
	return k, mapErr(err)
}

// CreateAPIKey inserts a key.
func (s *Store) CreateAPIKey(ctx context.Context, db DBTX, k APIKey) error {
	_, err := db.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, project_id, name, lookup_id, secret_hash, scopes,
		created_by, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10)`,
		k.ID, k.TenantID, k.ProjectID, k.Name, k.LookupID, k.SecretHash, k.Scopes, k.CreatedBy, k.CreatedAt, k.ExpiresAt)
	return mapErr(err)
}

// GetAPIKeyByLookupID finds a key by the public identifier embedded in it.
// This is the only cross-tenant lookup and is used solely for authentication;
// the caller must compare the secret hash in constant time.
func (s *Store) GetAPIKeyByLookupID(ctx context.Context, lookupID string) (APIKey, error) {
	return scanAPIKey(s.Pool.QueryRow(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE lookup_id = $1`, lookupID))
}

// GetAPIKey returns a key of the project.
func (s *Store) GetAPIKey(ctx context.Context, tenantID, projectID, keyID string) (APIKey, error) {
	return scanAPIKey(s.Pool.QueryRow(ctx, `SELECT `+apiKeyColumns+` FROM api_keys
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3`, tenantID, projectID, keyID))
}

// ListAPIKeys returns the project's keys, newest first.
func (s *Store) ListAPIKeys(ctx context.Context, tenantID, projectID string) ([]APIKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+apiKeyColumns+` FROM api_keys
		WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey revokes a key of the project. Revocation is permanent.
func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, projectID, keyID string, at time.Time) (APIKey, error) {
	return scanAPIKey(s.Pool.QueryRow(ctx, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $4)
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3 RETURNING `+apiKeyColumns, tenantID, projectID, keyID, at))
}

// TouchAPIKey records usage. Callers throttle it.
func (s *Store) TouchAPIKey(ctx context.Context, keyID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`, keyID, at)
	return err
}
