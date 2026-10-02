package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/pkg/integrity"
)

// Stream is an audit stream and its chain head.
type Stream struct {
	ID                     string
	TenantID               string
	ProjectID              string
	Name                   string
	HeadSequence           int64
	HeadHash               []byte
	HeadRecordedAt         *time.Time
	LastCheckpointSequence int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// Head returns the head as a verification target.
func (st *Stream) HeadHashValue() integrity.Hash {
	h, _ := integrity.HashFromBytes(st.HeadHash)
	return h
}

// StreamSummary adds the latest verification to a stream.
type StreamSummary struct {
	Stream
	LastVerification *StreamVerification
}

const streamColumns = `s.id, s.tenant_id, s.project_id, s.name, s.head_sequence, s.head_hash, s.head_recorded_at,
	s.last_checkpoint_sequence, s.created_at, s.updated_at`

func scanStream(row interface{ Scan(...any) error }, extra ...any) (Stream, error) {
	var st Stream
	dest := []any{&st.ID, &st.TenantID, &st.ProjectID, &st.Name, &st.HeadSequence, &st.HeadHash, &st.HeadRecordedAt,
		&st.LastCheckpointSequence, &st.CreatedAt, &st.UpdatedAt}
	err := row.Scan(append(dest, extra...)...)
	return st, mapErr(err)
}

// GetStream returns a stream of the project by name.
func (s *Store) GetStream(ctx context.Context, tenantID, projectID, name string) (Stream, error) {
	return scanStream(s.Pool.QueryRow(ctx, `SELECT `+streamColumns+` FROM audit_streams s
		WHERE s.tenant_id = $1 AND s.project_id = $2 AND s.name = $3`, tenantID, projectID, name))
}

// GetStreamByID returns a stream of the project by id.
func (s *Store) GetStreamByID(ctx context.Context, tenantID, projectID, streamID string) (Stream, error) {
	return scanStream(s.Pool.QueryRow(ctx, `SELECT `+streamColumns+` FROM audit_streams s
		WHERE s.tenant_id = $1 AND s.project_id = $2 AND s.id = $3`, tenantID, projectID, streamID))
}

// CountStreams returns the number of streams in the project.
func (s *Store) CountStreams(ctx context.Context, db DBTX, tenantID, projectID string) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM audit_streams WHERE tenant_id = $1 AND project_id = $2`,
		tenantID, projectID).Scan(&n)
	return n, err
}

// ListStreams returns the project's streams with their latest verification.
func (s *Store) ListStreams(ctx context.Context, tenantID, projectID string) ([]StreamSummary, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+streamColumns+`,
			lv.run_id, lv.valid, lv.events_checked, lv.first_sequence, lv.last_sequence, lv.failure_count,
			lv.first_failure_sequence, lv.completed_at
		FROM audit_streams s
		LEFT JOIN LATERAL (
			SELECT run_id, valid, events_checked, first_sequence, last_sequence, failure_count,
			       first_failure_sequence, completed_at
			  FROM stream_verifications sv WHERE sv.stream_id = s.id
			 ORDER BY completed_at DESC LIMIT 1) lv ON true
		WHERE s.tenant_id = $1 AND s.project_id = $2
		ORDER BY s.name`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StreamSummary
	for rows.Next() {
		var (
			runID                     *string
			valid                     *bool
			checked, failures         *int64
			first, last, firstFailure *int64
			completed                 *time.Time
		)
		st, err := scanStream(rows, &runID, &valid, &checked, &first, &last, &failures, &firstFailure, &completed)
		if err != nil {
			return nil, err
		}
		sum := StreamSummary{Stream: st}
		if runID != nil {
			sum.LastVerification = &StreamVerification{RunID: *runID, StreamID: st.ID, Valid: *valid,
				EventsChecked: *checked, FirstSequence: first, LastSequence: last, FailureCount: int(*failures),
				FirstFailureSequence: firstFailure, CompletedAt: *completed}
		}
		out = append(out, sum)
	}
	return out, rows.Err()
}

// ListAllStreams returns every stream (background jobs only).
func (s *Store) ListAllStreams(ctx context.Context) ([]Stream, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+streamColumns+` FROM audit_streams s ORDER BY s.project_id, s.name`)
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

// Event is a stored audit event.
type Event struct {
	ID            string
	TenantID      string
	ProjectID     string
	StreamID      string
	StreamName    string
	Sequence      int64
	SchemaVersion int
	ActorType     string
	ActorID       string
	Action        string
	ResourceType  *string
	ResourceID    *string
	OccurredAt    *time.Time
	RecordedAt    time.Time
	Content       string
	PayloadHash   []byte
	PreviousHash  []byte
	EventHash     []byte
	SigningKeyID  string
	Signature     []byte
}

func hashOrZero(b []byte) integrity.Hash {
	var h integrity.Hash
	copy(h[:], b) // a wrong length cannot pass the CHECK constraints; if it did, verification reports a mismatch
	return h
}

// Record converts the row into a chain record. The stream name comes from the
// stream being read, not from the row, so a row moved between streams fails
// verification.
func (e *Event) Record() integrity.Record {
	return integrity.Record{
		Header: integrity.Header{
			SchemaVersion: e.SchemaVersion,
			TenantID:      e.TenantID,
			ProjectID:     e.ProjectID,
			Stream:        e.StreamName,
			Sequence:      e.Sequence,
			EventID:       e.ID,
			RecordedAt:    integrity.FormatTime(e.RecordedAt),
			PreviousHash:  hashOrZero(e.PreviousHash),
			PayloadHash:   hashOrZero(e.PayloadHash),
			KeyID:         e.SigningKeyID,
		},
		EventHash: hashOrZero(e.EventHash),
		Signature: append([]byte(nil), e.Signature...),
		Content:   []byte(e.Content),
	}
}

// Index returns the denormalized index columns.
func (e *Event) Index() integrity.IndexFields {
	f := integrity.IndexFields{ActorType: e.ActorType, ActorID: e.ActorID, Action: e.Action}
	if e.ResourceType != nil {
		f.ResourceType = *e.ResourceType
	}
	if e.ResourceID != nil {
		f.ResourceID = *e.ResourceID
	}
	if e.OccurredAt != nil {
		f.OccurredAt = integrity.FormatTime(*e.OccurredAt)
	}
	return f
}

const eventColumns = `e.id, e.tenant_id, e.project_id, e.stream_id, s.name, e.sequence, e.schema_version,
	e.actor_type, e.actor_id, e.action, e.resource_type, e.resource_id, e.occurred_at, e.recorded_at, e.content,
	e.payload_hash, e.previous_hash, e.event_hash, e.signing_key_id, e.signature`

const eventFrom = ` FROM audit_events e JOIN audit_streams s ON s.id = e.stream_id `

func scanEvent(row interface{ Scan(...any) error }) (Event, error) {
	var e Event
	err := row.Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.StreamID, &e.StreamName, &e.Sequence, &e.SchemaVersion,
		&e.ActorType, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID, &e.OccurredAt, &e.RecordedAt, &e.Content,
		&e.PayloadHash, &e.PreviousHash, &e.EventHash, &e.SigningKeyID, &e.Signature)
	return e, mapErr(err)
}

func collectEvents(rows pgx.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertEvent appends an event row. Called by the appender inside its
// transaction; the link trigger re-checks contiguity and linkage.
func (s *Store) InsertEvent(ctx context.Context, db DBTX, e Event) error {
	_, err := db.Exec(ctx, insertEventSQL, insertEventArgs(e)...)
	return mapErr(err)
}

const insertEventSQL = `INSERT INTO audit_events (id, tenant_id, project_id, stream_id, sequence, schema_version,
	actor_type, actor_id, action, resource_type, resource_id, occurred_at, recorded_at, content, payload_hash,
	previous_hash, event_hash, signing_key_id, signature)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

func insertEventArgs(e Event) []any {
	return []any{e.ID, e.TenantID, e.ProjectID, e.StreamID, e.Sequence, e.SchemaVersion, e.ActorType, e.ActorID,
		e.Action, e.ResourceType, e.ResourceID, e.OccurredAt, e.RecordedAt, e.Content, e.PayloadHash, e.PreviousHash,
		e.EventHash, e.SigningKeyID, e.Signature}
}

// QueueInsertEvent adds an insert to a pgx batch.
func QueueInsertEvent(b *pgx.Batch, e Event) {
	b.Queue(insertEventSQL, insertEventArgs(e)...)
}

// GetEvent returns an event of the project.
func (s *Store) GetEvent(ctx context.Context, tenantID, projectID, eventID string) (Event, error) {
	return scanEvent(s.Pool.QueryRow(ctx, `SELECT `+eventColumns+eventFrom+`
		WHERE e.tenant_id = $1 AND e.project_id = $2 AND e.id = $3`, tenantID, projectID, eventID))
}

// GetEventsByIDs returns events of the project in the order of ids.
func (s *Store) GetEventsByIDs(ctx context.Context, tenantID, projectID string, ids []string) ([]Event, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+eventColumns+eventFrom+`
		WHERE e.tenant_id = $1 AND e.project_id = $2 AND e.id = ANY($3)`, tenantID, projectID, ids)
	if err != nil {
		return nil, err
	}
	events, err := collectEvents(rows)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]Event, len(events))
	for _, e := range events {
		byID[e.ID] = e
	}
	out := make([]Event, 0, len(ids))
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetEventBySequence returns the event at a sequence of a stream.
func (s *Store) GetEventBySequence(ctx context.Context, tenantID, projectID, streamID string, seq int64) (Event, error) {
	return scanEvent(s.Pool.QueryRow(ctx, `SELECT `+eventColumns+eventFrom+`
		WHERE e.tenant_id = $1 AND e.project_id = $2 AND e.stream_id = $3 AND e.sequence = $4`,
		tenantID, projectID, streamID, seq))
}

// ChainPage returns up to limit events of a stream with sequence > after, in
// ascending order. This is what verification reads.
func (s *Store) ChainPage(ctx context.Context, tenantID, projectID, streamID string, after int64, limit int) ([]Event, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+eventColumns+eventFrom+`
		WHERE e.tenant_id = $1 AND e.project_id = $2 AND e.stream_id = $3 AND e.sequence > $4
		ORDER BY e.sequence ASC LIMIT $5`, tenantID, projectID, streamID, after, limit)
	if err != nil {
		return nil, err
	}
	return collectEvents(rows)
}

// ChainRange returns the events of a stream with from <= sequence <= to.
func (s *Store) ChainRange(ctx context.Context, tenantID, projectID, streamID string, from, to int64, limit int) ([]Event, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+eventColumns+eventFrom+`
		WHERE e.tenant_id = $1 AND e.project_id = $2 AND e.stream_id = $3 AND e.sequence BETWEEN $4 AND $5
		ORDER BY e.sequence ASC LIMIT $6`, tenantID, projectID, streamID, from, to, limit)
	if err != nil {
		return nil, err
	}
	return collectEvents(rows)
}

// SequenceRangeForTime maps a recorded_at window [from, to) to the contiguous
// sequence range it covers. recorded_at is non-decreasing within a stream, so
// the range is contiguous. ok is false when no event falls in the window.
func (s *Store) SequenceRangeForTime(ctx context.Context, tenantID, projectID, streamID string, from, to *time.Time) (int64, int64, bool, error) {
	var lo, hi *int64
	err := s.Pool.QueryRow(ctx, `SELECT min(sequence), max(sequence) FROM audit_events
		WHERE tenant_id = $1 AND project_id = $2 AND stream_id = $3
		  AND ($4::timestamptz IS NULL OR recorded_at >= $4) AND ($5::timestamptz IS NULL OR recorded_at < $5)`,
		tenantID, projectID, streamID, from, to).Scan(&lo, &hi)
	if err != nil {
		return 0, 0, false, err
	}
	if lo == nil || hi == nil {
		return 0, 0, false, nil
	}
	return *lo, *hi, true, nil
}

// EventFilter selects events for listing.
type EventFilter struct {
	TenantID     string
	ProjectID    string
	Stream       string
	ActorID      string
	ActorType    string
	Action       string // exact, or prefix when it ends with '*'
	ResourceType string
	ResourceID   string
	From         *time.Time
	To           *time.Time
	// Status filters by the latest verification of each stream:
	// "verified", "failed" or "unverified".
	Status string
	Limit  int
	// Cursor (exclusive): events strictly older than this position.
	CursorTime *time.Time
	CursorID   string
}

// ListEvents returns events, newest first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	var (
		where = []string{"e.tenant_id = $1", "e.project_id = $2"}
		args  = []any{f.TenantID, f.ProjectID}
	)
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.Stream != "" {
		add("s.name = $%d", f.Stream)
	}
	if f.ActorID != "" {
		add("e.actor_id = $%d", f.ActorID)
	}
	if f.ActorType != "" {
		add("e.actor_type = $%d", f.ActorType)
	}
	if f.Action != "" {
		if prefix, ok := strings.CutSuffix(f.Action, "*"); ok {
			add("e.action LIKE $%d", escapeLike(prefix)+"%")
		} else {
			add("e.action = $%d", f.Action)
		}
	}
	if f.ResourceType != "" {
		add("e.resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("e.resource_id = $%d", f.ResourceID)
	}
	if f.From != nil {
		add("e.recorded_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("e.recorded_at < $%d", *f.To)
	}
	if f.CursorTime != nil {
		args = append(args, *f.CursorTime, f.CursorID)
		where = append(where, fmt.Sprintf("(e.recorded_at, e.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	join := ""
	switch f.Status {
	case "verified":
		join = latestVerificationJoin
		where = append(where, "lv.last_sequence IS NOT NULL AND e.sequence <= lv.last_sequence AND (lv.first_failure_sequence IS NULL OR e.sequence < lv.first_failure_sequence)")
	case "failed":
		join = latestVerificationJoin
		where = append(where, "lv.first_failure_sequence IS NOT NULL AND e.sequence >= lv.first_failure_sequence AND e.sequence <= lv.last_sequence")
	case "unverified":
		join = latestVerificationJoin
		where = append(where, "(lv.last_sequence IS NULL OR e.sequence > lv.last_sequence)")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	args = append(args, limit)
	query := `SELECT ` + eventColumns + eventFrom + join + ` WHERE ` + strings.Join(where, " AND ") +
		fmt.Sprintf(` ORDER BY e.recorded_at DESC, e.id DESC LIMIT $%d`, len(args))
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return collectEvents(rows)
}

const latestVerificationJoin = ` LEFT JOIN LATERAL (
	SELECT last_sequence, first_failure_sequence FROM stream_verifications sv
	 WHERE sv.stream_id = e.stream_id ORDER BY completed_at DESC LIMIT 1) lv ON true `

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// ProjectStats summarizes a project for the overview page.
type ProjectStats struct {
	EventsTotal   int64
	EventsToday   int64
	Streams       int
	ActiveStreams int
	LastEventAt   *time.Time
}

// GetProjectStats computes overview statistics. "Today" is the UTC day.
func (s *Store) GetProjectStats(ctx context.Context, tenantID, projectID string, now time.Time) (ProjectStats, error) {
	var st ProjectStats
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(sum(head_sequence), 0), count(*),
			count(*) FILTER (WHERE head_recorded_at >= $3), max(head_recorded_at)
		FROM audit_streams WHERE tenant_id = $1 AND project_id = $2`,
		tenantID, projectID, now.Add(-7*24*time.Hour)).Scan(&st.EventsTotal, &st.Streams, &st.ActiveStreams, &st.LastEventAt)
	if err != nil {
		return st, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE project_id = $1 AND tenant_id = $2 AND recorded_at >= $3`,
		projectID, tenantID, dayStart).Scan(&st.EventsToday)
	return st, err
}

// DayCount is the number of events recorded on a UTC day.
type DayCount struct {
	Day   time.Time
	Count int64
}

// EventsPerDay returns counts for the last n UTC days, oldest first, including
// days without events.
func (s *Store) EventsPerDay(ctx context.Context, tenantID, projectID string, now time.Time, days int) ([]DayCount, error) {
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	start := end.AddDate(0, 0, -days)
	rows, err := s.Pool.Query(ctx, `SELECT date_trunc('day', recorded_at AT TIME ZONE 'UTC') AS day, count(*)
		FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND recorded_at >= $3 AND recorded_at < $4
		GROUP BY day ORDER BY day`, tenantID, projectID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var day time.Time
		var n int64
		if err := rows.Scan(&day, &n); err != nil {
			return nil, err
		}
		counts[day.Format("2006-01-02")] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]DayCount, 0, days)
	for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
		out = append(out, DayCount{Day: d, Count: counts[d.Format("2006-01-02")]})
	}
	return out, nil
}
