package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

// Errors returned by the appender.
var (
	ErrIdempotencyMismatch = errors.New("idempotency key was already used with a different request")
	ErrTooManyStreams      = errors.New("project stream limit reached")
)

// Appender commits events to hash chains.
type Appender struct {
	store      *store.Store
	keys       *keys.Manager
	now        func() time.Time
	maxStreams int
	idemTTL    time.Duration
}

// AppenderOptions configure an Appender.
type AppenderOptions struct {
	MaxStreamsPerProject int
	IdempotencyTTL       time.Duration
	// Now overrides the clock (tests and demo data only).
	Now func() time.Time
}

// NewAppender returns an Appender.
func NewAppender(st *store.Store, km *keys.Manager, opts AppenderOptions) *Appender {
	a := &Appender{store: st, keys: km, now: opts.Now, maxStreams: opts.MaxStreamsPerProject, idemTTL: opts.IdempotencyTTL}
	if a.now == nil {
		a.now = time.Now
	}
	if a.maxStreams <= 0 {
		a.maxStreams = 1000
	}
	if a.idemTTL <= 0 {
		a.idemTTL = 7 * 24 * time.Hour
	}
	return a
}

// AppendRequest is one ingestion request (single event or batch).
type AppendRequest struct {
	TenantID  string
	ProjectID string
	Events    []Prepared
	// IdempotencyKey, when set, makes the request safely retryable.
	IdempotencyKey string
	RequestHash    [32]byte
	Endpoint       string
}

// Committed is a committed event.
type Committed struct {
	Record   integrity.Record
	StreamID string
}

// AppendResult is the outcome of a request.
type AppendResult struct {
	Events   []Committed
	Replayed bool
}

type streamState struct {
	id       string
	name     string
	headSeq  int64
	headHash integrity.Hash
	headTime *time.Time
}

// Append commits all events of the request atomically: either every event is
// appended to its stream or none is.
func (a *Appender) Append(ctx context.Context, req AppendRequest) (AppendResult, error) {
	if len(req.Events) == 0 {
		return AppendResult{}, errors.New("audit: no events to append")
	}
	if req.IdempotencyKey != "" {
		if res, ok, err := a.replay(ctx, req); err != nil || ok {
			return res, err
		}
	}

	var result AppendResult
	err := a.store.InTx(ctx, func(tx pgx.Tx) error {
		result = AppendResult{}
		states, err := a.lockStreams(ctx, tx, req)
		if err != nil {
			return err
		}
		keyID, err := a.activeKey(ctx, tx, req.TenantID, req.ProjectID)
		if err != nil {
			return err
		}
		signer, err := a.keys.Signer(ctx, keyID)
		if err != nil {
			return err
		}

		batch := &pgx.Batch{}
		for _, ev := range req.Events {
			st := states[ev.Stream]
			recorded := a.now().UTC().Truncate(time.Microsecond)
			if st.headTime != nil && recorded.Before(*st.headTime) {
				// recordedAt never decreases within a stream, even if this
				// server's clock is behind the one that wrote the head.
				recorded = *st.headTime
			}
			rec, err := integrity.Seal(ctx, integrity.SealInput{
				TenantID:         req.TenantID,
				ProjectID:        req.ProjectID,
				Stream:           st.name,
				Sequence:         st.headSeq + 1,
				EventID:          id.New(id.Event),
				RecordedAt:       recorded,
				PreviousHash:     st.headHash,
				CanonicalContent: ev.Content,
			}, signer)
			if err != nil {
				return err
			}
			store.QueueInsertEvent(batch, eventRow(rec, st.id, ev))
			result.Events = append(result.Events, Committed{Record: rec, StreamID: st.id})
			st.headSeq, st.headHash, st.headTime = rec.Sequence, rec.EventHash, &recorded
		}
		for _, st := range states {
			batch.Queue(`UPDATE audit_streams SET head_sequence = $2, head_hash = $3, head_recorded_at = $4, updated_at = now()
				WHERE id = $1`, st.id, st.headSeq, st.headHash[:], *st.headTime)
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("audit: insert events: %w", err)
		}

		if req.IdempotencyKey != "" {
			ids := make([]string, len(result.Events))
			for i, c := range result.Events {
				ids[i] = c.Record.EventID
			}
			now := a.now().UTC()
			inserted, err := a.store.InsertIdempotency(ctx, tx, store.IdempotencyRecord{
				ProjectID: req.ProjectID, Key: req.IdempotencyKey, Endpoint: req.Endpoint,
				RequestHash: req.RequestHash[:], EventIDs: ids, CreatedAt: now, ExpiresAt: now.Add(a.idemTTL),
			})
			if err != nil {
				return err
			}
			if !inserted {
				return errConcurrentIdempotentRequest
			}
		}
		return nil
	})
	if errors.Is(err, errConcurrentIdempotentRequest) {
		// A concurrent request with the same key committed first; our
		// transaction rolled back. Answer exactly as a retry would be answered.
		res, ok, rerr := a.replay(ctx, req)
		if rerr != nil {
			return AppendResult{}, rerr
		}
		if ok {
			return res, nil
		}
		return AppendResult{}, errors.New("audit: idempotency record vanished")
	}
	return result, err
}

var errConcurrentIdempotentRequest = errors.New("audit: concurrent request with the same idempotency key")

// activeKey share-locks the project's active signing key.
//
// If a rotation commits while we wait for its row lock, PostgreSQL re-checks
// the updated row, finds it retired and returns no row: the new key was
// inserted after this statement's snapshot. A new statement takes a new
// snapshot (READ COMMITTED), so retrying finds the new key.
func (a *Appender) activeKey(ctx context.Context, tx pgx.Tx, tenantID, projectID string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		keyID, err := a.store.ActiveSigningKeyShared(ctx, tx, tenantID, projectID)
		if err == nil {
			return keyID, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
	}
	return "", keys.ErrNoActiveKey
}

// replay answers a retried request from its idempotency record.
func (a *Appender) replay(ctx context.Context, req AppendRequest) (AppendResult, bool, error) {
	rec, err := a.store.GetIdempotency(ctx, a.store.Pool, req.ProjectID, req.IdempotencyKey, a.now())
	if errors.Is(err, store.ErrNotFound) {
		return AppendResult{}, false, nil
	}
	if err != nil {
		return AppendResult{}, false, err
	}
	if rec.Endpoint != req.Endpoint || !bytes.Equal(rec.RequestHash, req.RequestHash[:]) {
		return AppendResult{}, false, ErrIdempotencyMismatch
	}
	events, err := a.store.GetEventsByIDs(ctx, req.TenantID, req.ProjectID, rec.EventIDs)
	if err != nil {
		return AppendResult{}, false, err
	}
	if len(events) != len(rec.EventIDs) {
		return AppendResult{}, false, errors.New("audit: events referenced by an idempotency record are missing")
	}
	res := AppendResult{Replayed: true}
	for _, e := range events {
		res.Events = append(res.Events, Committed{Record: e.Record(), StreamID: e.StreamID})
	}
	return res, true, nil
}

// lockStreams creates missing streams and locks every involved stream row in
// sorted order, which rules out deadlocks between concurrent batches.
func (a *Appender) lockStreams(ctx context.Context, tx pgx.Tx, req AppendRequest) (map[string]*streamState, error) {
	names := make([]string, 0, len(req.Events))
	seen := map[string]bool{}
	for _, ev := range req.Events {
		if !seen[ev.Stream] {
			seen[ev.Stream] = true
			names = append(names, ev.Stream)
		}
	}
	sort.Strings(names)
	states := make(map[string]*streamState, len(names))
	for _, name := range names {
		st, err := a.lockStream(ctx, tx, req.TenantID, req.ProjectID, name)
		if err != nil {
			return nil, err
		}
		states[name] = st
	}
	return states, nil
}

func (a *Appender) lockStream(ctx context.Context, tx pgx.Tx, tenantID, projectID, name string) (*streamState, error) {
	lock := func() (*streamState, error) {
		st := &streamState{name: name}
		var head []byte
		err := tx.QueryRow(ctx, `SELECT id, head_sequence, head_hash, head_recorded_at FROM audit_streams
			WHERE tenant_id = $1 AND project_id = $2 AND name = $3 FOR UPDATE`, tenantID, projectID, name).
			Scan(&st.id, &st.headSeq, &head, &st.headTime)
		if err != nil {
			return nil, err
		}
		copy(st.headHash[:], head)
		return st, nil
	}
	st, err := lock()
	if err == nil {
		return st, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	count, err := a.store.CountStreams(ctx, tx, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	if count >= a.maxStreams {
		return nil, fmt.Errorf("%w (%d)", ErrTooManyStreams, a.maxStreams)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_streams (id, tenant_id, project_id, name) VALUES ($1, $2, $3, $4)
		ON CONFLICT (project_id, name) DO NOTHING`, id.New(id.Stream), tenantID, projectID, name); err != nil {
		return nil, err
	}
	return lock()
}

func eventRow(rec integrity.Record, streamID string, ev Prepared) store.Event {
	row := store.Event{
		ID:            rec.EventID,
		TenantID:      rec.TenantID,
		ProjectID:     rec.ProjectID,
		StreamID:      streamID,
		Sequence:      rec.Sequence,
		SchemaVersion: rec.SchemaVersion,
		ActorType:     ev.Index.ActorType,
		ActorID:       ev.Index.ActorID,
		Action:        ev.Index.Action,
		OccurredAt:    ev.OccurredAt,
		Content:       string(rec.Content),
		PayloadHash:   rec.PayloadHash[:],
		PreviousHash:  rec.PreviousHash[:],
		EventHash:     rec.EventHash[:],
		SigningKeyID:  rec.KeyID,
		Signature:     rec.Signature,
	}
	if t, err := integrity.ParseTime(rec.RecordedAt); err == nil {
		row.RecordedAt = t
	}
	if ev.Index.ResourceType != "" {
		rt, rid := ev.Index.ResourceType, ev.Index.ResourceID
		row.ResourceType, row.ResourceID = &rt, &rid
	}
	return row
}
