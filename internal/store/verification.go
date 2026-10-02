package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// VerificationRun is one verification of an event, stream or project.
type VerificationRun struct {
	ID             string
	TenantID       string
	ProjectID      string
	Scope          string
	Target         string
	Status         string
	Trigger        string
	TriggeredBy    string
	StreamsChecked int
	EventsChecked  int64
	FailureCount   int
	Report         json.RawMessage
	Error          string
	StartedAt      time.Time
	CompletedAt    *time.Time
}

// StreamVerification is the per-stream outcome of a run.
type StreamVerification struct {
	RunID                string
	StreamID             string
	ProjectID            string
	Valid                bool
	EventsChecked        int64
	FirstSequence        *int64
	LastSequence         *int64
	FailureCount         int
	FirstFailureSequence *int64
	FailureSequences     []int64
	FirstFailure         json.RawMessage
	CompletedAt          time.Time
}

const runColumns = `id, tenant_id, project_id, scope, COALESCE(target, ''), status, trigger, COALESCE(triggered_by, ''),
	streams_checked, events_checked, failure_count, report, COALESCE(error, ''), started_at, completed_at`

func scanRun(row interface{ Scan(...any) error }) (VerificationRun, error) {
	var r VerificationRun
	err := row.Scan(&r.ID, &r.TenantID, &r.ProjectID, &r.Scope, &r.Target, &r.Status, &r.Trigger, &r.TriggeredBy,
		&r.StreamsChecked, &r.EventsChecked, &r.FailureCount, &r.Report, &r.Error, &r.StartedAt, &r.CompletedAt)
	return r, mapErr(err)
}

// CreateVerificationRun inserts a run in the "running" state.
func (s *Store) CreateVerificationRun(ctx context.Context, r VerificationRun) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO verification_runs (id, tenant_id, project_id, scope, target, status, trigger,
		triggered_by, started_at) VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'running', $6, NULLIF($7, ''), $8)`,
		r.ID, r.TenantID, r.ProjectID, r.Scope, r.Target, r.Trigger, r.TriggeredBy, r.StartedAt)
	return mapErr(err)
}

// CompleteVerificationRun stores the outcome of a run and its per-stream
// results atomically.
func (s *Store) CompleteVerificationRun(ctx context.Context, r VerificationRun, streams []StreamVerification) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE verification_runs SET status = $3, streams_checked = $4, events_checked = $5,
			failure_count = $6, report = $7, error = NULLIF($8, ''), completed_at = $9
			WHERE tenant_id = $1 AND id = $2`,
			r.TenantID, r.ID, r.Status, r.StreamsChecked, r.EventsChecked, r.FailureCount, r.Report, r.Error, r.CompletedAt)
		if err != nil {
			return err
		}
		for _, sv := range streams {
			seqs := sv.FailureSequences
			if seqs == nil {
				seqs = []int64{}
			}
			_, err := tx.Exec(ctx, `INSERT INTO stream_verifications (run_id, stream_id, project_id, valid, events_checked,
				first_sequence, last_sequence, failure_count, first_failure_sequence, failure_sequences, first_failure,
				completed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
				r.ID, sv.StreamID, r.ProjectID, sv.Valid, sv.EventsChecked, sv.FirstSequence, sv.LastSequence,
				sv.FailureCount, sv.FirstFailureSequence, seqs, sv.FirstFailure, sv.CompletedAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetVerificationRun returns a run of the project.
func (s *Store) GetVerificationRun(ctx context.Context, tenantID, projectID, runID string) (VerificationRun, error) {
	return scanRun(s.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM verification_runs
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3`, tenantID, projectID, runID))
}

// ListVerificationRuns returns the newest runs of the project. Reports are
// omitted to keep listings small.
func (s *Store) ListVerificationRuns(ctx context.Context, tenantID, projectID string, limit int) ([]VerificationRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, tenant_id, project_id, scope, COALESCE(target, ''), status, trigger,
			COALESCE(triggered_by, ''), streams_checked, events_checked, failure_count, NULL::jsonb, COALESCE(error, ''),
			started_at, completed_at
		FROM verification_runs WHERE tenant_id = $1 AND project_id = $2 ORDER BY started_at DESC LIMIT $3`,
		tenantID, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerificationRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestVerificationRun returns the newest completed run, if any.
func (s *Store) LatestVerificationRun(ctx context.Context, tenantID, projectID string) (VerificationRun, error) {
	return scanRun(s.Pool.QueryRow(ctx, `SELECT id, tenant_id, project_id, scope, COALESCE(target, ''), status, trigger,
			COALESCE(triggered_by, ''), streams_checked, events_checked, failure_count, NULL::jsonb, COALESCE(error, ''),
			started_at, completed_at
		FROM verification_runs WHERE tenant_id = $1 AND project_id = $2 AND completed_at IS NOT NULL
		  AND scope IN ('stream', 'project')
		ORDER BY completed_at DESC LIMIT 1`, tenantID, projectID))
}

// LatestStreamVerification returns the newest result for a stream.
func (s *Store) LatestStreamVerification(ctx context.Context, projectID, streamID string) (StreamVerification, error) {
	var sv StreamVerification
	err := s.Pool.QueryRow(ctx, `SELECT run_id, stream_id, project_id, valid, events_checked, first_sequence,
			last_sequence, failure_count, first_failure_sequence, failure_sequences, first_failure, completed_at
		FROM stream_verifications WHERE project_id = $1 AND stream_id = $2 ORDER BY completed_at DESC LIMIT 1`,
		projectID, streamID).Scan(&sv.RunID, &sv.StreamID, &sv.ProjectID, &sv.Valid, &sv.EventsChecked,
		&sv.FirstSequence, &sv.LastSequence, &sv.FailureCount, &sv.FirstFailureSequence, &sv.FailureSequences,
		&sv.FirstFailure, &sv.CompletedAt)
	return sv, mapErr(err)
}
