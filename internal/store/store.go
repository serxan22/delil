// Package store contains DƏLİL's PostgreSQL repositories.
//
// Tenant isolation rule: every method that reads or writes tenant data takes
// the tenant and project identifiers derived from the authenticated principal
// and includes them in the WHERE clause, even when a primary key alone would
// identify the row. Lookups that miss return ErrNotFound, never a different
// tenant's data and never an error that reveals existence.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors returned by repositories.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// DBTX is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store wraps the connection pool.
type Store struct {
	Pool *pgxpool.Pool
}

// New returns a Store.
func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// InTx runs fn in a transaction, committing if it returns nil.
func (s *Store) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.Pool, fn)
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case IsUniqueViolation(err):
		return errors.Join(ErrConflict, err)
	}
	return err
}

// IsUniqueViolation reports whether err is a PostgreSQL unique violation.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsCheckViolation reports whether err is a PostgreSQL check violation,
// which DƏLİL's integrity triggers raise.
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}

// IsInsufficientPrivilege reports whether err was raised by an append-only
// guard or by missing grants.
func IsInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
