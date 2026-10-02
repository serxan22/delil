package store

import (
	"context"
	"time"
)

// User is a dashboard user. Users belong to exactly one tenant.
type User struct {
	ID           string
	TenantID     string
	Email        string
	DisplayName  string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
	LastLoginAt  *time.Time
	DisabledAt   *time.Time
}

// Session is a dashboard session. Only the SHA-256 of the token is stored.
type Session struct {
	ID         string
	TokenHash  []byte
	UserID     string
	TenantID   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
	IP         string
	UserAgent  string
}

const userColumns = `id, tenant_id, email, display_name, password_hash, role, created_at, last_login_at, disabled_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role,
		&u.CreatedAt, &u.LastLoginAt, &u.DisabledAt)
	return u, mapErr(err)
}

// CreateUser inserts a user. The email must already be lowercased.
func (s *Store) CreateUser(ctx context.Context, db DBTX, u User) error {
	_, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, email, display_name, password_hash, role, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.TenantID, u.Email, u.DisplayName, u.PasswordHash, u.Role, u.CreatedAt)
	return mapErr(err)
}

// GetUserByEmail returns a user by email (login only).
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email))
}

// GetUser returns a user of the tenant.
func (s *Store) GetUser(ctx context.Context, tenantID, userID string) (User, error) {
	return scanUser(s.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND id = $2`,
		tenantID, userID))
}

// ListUsers returns the tenant's users.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userColumns+` FROM users WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserPassword replaces a user's password hash.
func (s *Store) SetUserPassword(ctx context.Context, tenantID, userID, hash string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE users SET password_hash = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, userID, hash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchUserLogin records a successful login.
func (s *Store) TouchUserLogin(ctx context.Context, userID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, userID, at)
	return err
}

// CreateSession inserts a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO sessions (id, token_hash, user_id, tenant_id, created_at, expires_at,
		last_seen_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sess.ID, sess.TokenHash, sess.UserID, sess.TenantID, sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt,
		sess.IP, sess.UserAgent)
	return mapErr(err)
}

// GetActiveSession resolves a token hash to a live session and its user.
func (s *Store) GetActiveSession(ctx context.Context, tokenHash []byte, now time.Time) (Session, User, error) {
	var sess Session
	row := s.Pool.QueryRow(ctx, `SELECT s.id, s.token_hash, s.user_id, s.tenant_id, s.created_at, s.expires_at,
			s.last_seen_at, s.revoked_at, COALESCE(s.ip, ''), COALESCE(s.user_agent, ''),
			u.id, u.tenant_id, u.email, u.display_name, u.password_hash, u.role, u.created_at, u.last_login_at, u.disabled_at
		FROM sessions s JOIN users u ON u.id = s.user_id AND u.tenant_id = s.tenant_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND u.disabled_at IS NULL`,
		tokenHash, now)
	var u User
	err := row.Scan(&sess.ID, &sess.TokenHash, &sess.UserID, &sess.TenantID, &sess.CreatedAt, &sess.ExpiresAt,
		&sess.LastSeenAt, &sess.RevokedAt, &sess.IP, &sess.UserAgent,
		&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.LastLoginAt, &u.DisabledAt)
	return sess, u, mapErr(err)
}

// TouchSession updates last_seen_at.
func (s *Store) TouchSession(ctx context.Context, sessionID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, sessionID, at)
	return err
}

// RevokeSession revokes one session.
func (s *Store) RevokeSession(ctx context.Context, sessionID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, sessionID, at)
	return err
}

// RevokeOtherSessions revokes every session of the user except keepID.
func (s *Store) RevokeOtherSessions(ctx context.Context, userID, keepID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = $3 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
		userID, keepID, at)
	return err
}

// DeleteExpiredSessions removes sessions that expired or were revoked before cutoff.
func (s *Store) DeleteExpiredSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR revoked_at < $1`, cutoff)
	return tag.RowsAffected(), err
}
