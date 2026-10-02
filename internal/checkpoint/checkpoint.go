// Package checkpoint creates signed checkpoints of stream heads and publishes
// them to external anchors.
//
// A checkpoint stored next to the chain only helps against attackers who
// cannot also delete it. Its real value appears when it leaves the database:
// saved by an auditor (a witness), written to WORM storage, or timestamped by
// a third party. The Anchor interface is that extension point.
package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

// ErrEmptyStream means the stream has no events to checkpoint.
var ErrEmptyStream = errors.New("checkpoint: stream has no events")

// Anchor publishes a checkpoint outside the database and returns a receipt.
// Future providers: RFC 3161 timestamp authorities, object storage with
// retention locks, transparency logs.
type Anchor interface {
	Name() string
	Anchor(ctx context.Context, cp integrity.Checkpoint) (json.RawMessage, error)
}

// Service creates checkpoints.
type Service struct {
	store   *store.Store
	keys    *keys.Manager
	anchors []Anchor
	log     *slog.Logger
	now     func() time.Time
}

// NewService returns a Service.
func NewService(st *store.Store, km *keys.Manager, log *slog.Logger, anchors ...Anchor) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, keys: km, anchors: anchors, log: log, now: time.Now}
}

// CreateForStream signs the stream's current head. If a checkpoint already
// exists at that sequence it is returned unchanged (created is false).
func (s *Service) CreateForStream(ctx context.Context, st store.Stream) (store.Checkpoint, bool, error) {
	if st.HeadSequence == 0 {
		return store.Checkpoint{}, false, ErrEmptyStream
	}
	active, err := s.keys.EnsureActiveKey(ctx, st.TenantID, st.ProjectID)
	if err != nil {
		return store.Checkpoint{}, false, err
	}
	signer, err := s.keys.Signer(ctx, active.ID)
	if err != nil {
		return store.Checkpoint{}, false, err
	}
	cp, err := integrity.NewCheckpoint(ctx, signer, id.New(id.Checkpoint), st.TenantID, st.ProjectID, st.Name,
		st.HeadSequence, st.HeadHashValue(), s.now())
	if err != nil {
		return store.Checkpoint{}, false, err
	}
	createdAt, _ := integrity.ParseTime(cp.CreatedAt)
	row := store.Checkpoint{
		ID: cp.CheckpointID, TenantID: cp.TenantID, ProjectID: cp.ProjectID, StreamID: st.ID, StreamName: st.Name,
		Sequence: cp.Sequence, HeadHash: cp.HeadHash[:], CreatedAt: createdAt, CheckpointHash: cp.CheckpointHash[:],
		SigningKeyID: cp.KeyID, Signature: cp.Signature,
	}
	if err := s.store.InsertCheckpoint(ctx, row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			existing, err := s.existingAt(ctx, st, st.HeadSequence)
			return existing, false, err
		}
		return store.Checkpoint{}, false, err
	}
	s.publish(ctx, cp)
	return row, true, nil
}

func (s *Service) existingAt(ctx context.Context, st store.Stream, seq int64) (store.Checkpoint, error) {
	cp, err := s.store.LatestCheckpointAtOrBefore(ctx, st.TenantID, st.ProjectID, st.ID, seq)
	if err != nil {
		return store.Checkpoint{}, err
	}
	if cp.Sequence != seq {
		return store.Checkpoint{}, fmt.Errorf("checkpoint: conflict at sequence %d", seq)
	}
	return cp, nil
}

// Create checkpoints a stream identified by name.
func (s *Service) Create(ctx context.Context, tenantID, projectID, stream string) (store.Checkpoint, bool, error) {
	st, err := s.store.GetStream(ctx, tenantID, projectID, stream)
	if err != nil {
		return store.Checkpoint{}, false, err
	}
	return s.CreateForStream(ctx, st)
}

// RunOnce checkpoints streams with at least minEvents new events, or whose
// newest uncheckpointed event is older than maxAge. It returns how many
// checkpoints were created.
func (s *Service) RunOnce(ctx context.Context, minEvents int64, maxAge time.Duration) (int, error) {
	streams, err := s.store.StreamsNeedingCheckpoint(ctx, minEvents, maxAge, s.now(), 100)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, st := range streams {
		if _, ok, err := s.CreateForStream(ctx, st); err != nil {
			s.log.Error("checkpoint failed", "stream_id", st.ID, "error", err)
		} else if ok {
			created++
		}
	}
	return created, nil
}

func (s *Service) publish(ctx context.Context, cp integrity.Checkpoint) {
	for _, a := range s.anchors {
		receipt, err := a.Anchor(ctx, cp)
		status, msg := "anchored", ""
		if err != nil {
			status, msg = "failed", err.Error()
			s.log.Warn("checkpoint anchoring failed", "provider", a.Name(), "checkpoint_id", cp.CheckpointID, "error", err)
		}
		if err := s.store.InsertCheckpointAnchor(ctx, id.New(id.Anchor), cp.CheckpointID, a.Name(), status, receipt, msg); err != nil {
			s.log.Error("recording anchor result failed", "checkpoint_id", cp.CheckpointID, "error", err)
		}
	}
}

// FileAnchor writes every checkpoint as a JSON file into a directory. Point it
// at storage the database operators cannot rewrite (a WORM volume, an object
// store mount with retention lock, a separate host) to make checkpoints
// independent witnesses. Files are created exclusively and never overwritten.
type FileAnchor struct {
	Dir string
}

// Name implements Anchor.
func (f FileAnchor) Name() string { return "file" }

// Anchor implements Anchor.
func (f FileAnchor) Anchor(_ context.Context, cp integrity.Checkpoint) (json.RawMessage, error) {
	// Every path element is validated by the integrity package (ids and
	// stream names are restricted to safe characters).
	if !id.Valid(id.Tenant, cp.TenantID) || !id.Valid(id.Project, cp.ProjectID) || !integrity.ValidStreamName(cp.Stream) ||
		!id.Valid(id.Checkpoint, cp.CheckpointID) {
		return nil, errors.New("checkpoint: refusing to build a path from invalid identifiers")
	}
	dir := filepath.Join(f.Dir, cp.TenantID, cp.ProjectID, cp.Stream)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%012d-%s.json", cp.Sequence, cp.CheckpointID)
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440) //nolint:gosec // path built from validated identifiers above
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"path": filepath.Join(cp.TenantID, cp.ProjectID, cp.Stream, name)})
}
