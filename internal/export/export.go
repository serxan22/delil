// Package export builds evidence packages on the server. Exports are jobs
// stored in the exports table: a request inserts a pending job, a worker on
// any instance claims it with FOR UPDATE SKIP LOCKED, writes the package to
// the export directory and marks the job completed. Leases let another
// instance take over if a worker dies.
package export

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/integrity"
)

// Errors.
var (
	ErrEmptySelection = errors.New("the selection contains no events")
	ErrInvalidParams  = errors.New("invalid export parameters")
	ErrNotReady       = errors.New("export is not completed")
)

// Params select what to export.
type Params struct {
	Stream       string     `json:"stream"`
	From         *time.Time `json:"from,omitempty"`
	To           *time.Time `json:"to,omitempty"`
	FromSequence *int64     `json:"fromSequence,omitempty"`
	ToSequence   *int64     `json:"toSequence,omitempty"`
	ActorID      string     `json:"actorId,omitempty"`
	Action       string     `json:"action,omitempty"`
	ResourceType string     `json:"resourceType,omitempty"`
	ResourceID   string     `json:"resourceId,omitempty"`
}

// Filters returns the disclosure filters as a map.
func (p Params) Filters() map[string]string {
	f := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			f[k] = v
		}
	}
	set("actorId", p.ActorID)
	set("action", p.Action)
	set("resourceType", p.ResourceType)
	set("resourceId", p.ResourceID)
	return f
}

// Validate checks the parameters.
func (p Params) Validate() error {
	if !integrity.ValidStreamName(p.Stream) {
		return fmt.Errorf("%w: stream is required", ErrInvalidParams)
	}
	if p.From != nil && p.To != nil && !p.From.Before(*p.To) {
		return fmt.Errorf("%w: from must be before to", ErrInvalidParams)
	}
	if (p.From != nil || p.To != nil) && (p.FromSequence != nil || p.ToSequence != nil) {
		return fmt.Errorf("%w: select by time or by sequence, not both", ErrInvalidParams)
	}
	if p.FromSequence != nil && *p.FromSequence < 1 {
		return fmt.Errorf("%w: fromSequence must be at least 1", ErrInvalidParams)
	}
	if p.FromSequence != nil && p.ToSequence != nil && *p.ToSequence < *p.FromSequence {
		return fmt.Errorf("%w: toSequence must not be smaller than fromSequence", ErrInvalidParams)
	}
	for _, v := range []string{p.ActorID, p.Action, p.ResourceType, p.ResourceID} {
		if len(v) > 256 {
			return fmt.Errorf("%w: filter values are limited to 256 characters", ErrInvalidParams)
		}
	}
	return nil
}

// Service manages export jobs.
type Service struct {
	store      *store.Store
	keys       *keys.Manager
	verifier   *verification.Service
	dir        string
	ttl        time.Duration
	version    string
	log        *slog.Logger
	now        func() time.Time
	wake       chan struct{}
	maxAttempt int
}

// Options configure the service.
type Options struct {
	Dir     string
	TTL     time.Duration
	Version string
	Logger  *slog.Logger
}

// NewService returns a Service. dir must be writable.
func NewService(st *store.Store, km *keys.Manager, vs *verification.Service, opts Options) (*Service, error) {
	if opts.Dir == "" {
		return nil, errors.New("export: a storage directory is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	if opts.TTL <= 0 {
		opts.TTL = 7 * 24 * time.Hour
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Service{store: st, keys: km, verifier: vs, dir: opts.Dir, ttl: opts.TTL, version: opts.Version,
		log: opts.Logger, now: time.Now, wake: make(chan struct{}, 1), maxAttempt: 3}, nil
}

// Create validates params and queues an export.
func (s *Service) Create(ctx context.Context, tenantID, projectID string, p Params, createdBy string) (store.Export, error) {
	if err := p.Validate(); err != nil {
		return store.Export{}, err
	}
	st, err := s.store.GetStream(ctx, tenantID, projectID, p.Stream)
	if err != nil {
		return store.Export{}, err
	}
	params, err := json.Marshal(p)
	if err != nil {
		return store.Export{}, err
	}
	x := store.Export{ID: id.New(id.Export), TenantID: tenantID, ProjectID: projectID, StreamID: st.ID,
		StreamName: st.Name, Status: "pending", Params: params, CreatedBy: createdBy, CreatedAt: s.now().UTC()}
	if err := s.store.CreateExport(ctx, x); err != nil {
		return store.Export{}, err
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return x, nil
}

// Run processes jobs until ctx is cancelled.
func (s *Service) Run(ctx context.Context, poll time.Duration) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		for s.ProcessNext(ctx) {
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

// ProcessNext claims and builds one pending export. It reports whether a job
// was processed.
func (s *Service) ProcessNext(ctx context.Context) bool {
	x, err := s.store.ClaimExport(ctx, s.now(), 15*time.Minute, s.maxAttempt)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("claiming export failed", "error", err)
		}
		return false
	}
	if err := s.build(ctx, x); err != nil {
		s.log.Error("export failed", "export_id", x.ID, "attempt", x.Attempts, "error", err)
		attempts := s.maxAttempt
		if errors.Is(err, ErrEmptySelection) {
			attempts = 0 // deterministic: retrying cannot help
		}
		if ferr := s.store.FailExport(context.WithoutCancel(ctx), x.ID, err.Error(), attempts, s.now()); ferr != nil {
			s.log.Error("recording export failure failed", "export_id", x.ID, "error", ferr)
		}
	}
	return true
}

func (s *Service) path(x store.Export) (string, error) {
	if !id.Valid(id.Project, x.ProjectID) || !id.Valid(id.Export, x.ID) {
		return "", errors.New("export: invalid identifiers")
	}
	return filepath.Join(s.dir, x.ProjectID, x.ID+".zip"), nil
}

func (s *Service) build(ctx context.Context, x store.Export) error {
	var p Params
	if err := json.Unmarshal(x.Params, &p); err != nil {
		return err
	}
	st, err := s.store.GetStreamByID(ctx, x.TenantID, x.ProjectID, x.StreamID)
	if err != nil {
		return err
	}
	tenant, err := s.store.GetTenant(ctx, x.TenantID)
	if err != nil {
		return err
	}
	project, err := s.store.GetProject(ctx, x.TenantID, x.ProjectID)
	if err != nil {
		return err
	}

	from, to, err := s.selectRange(ctx, st, p)
	if err != nil {
		return err
	}
	anchorSeq, anchor, anchorCP, err := s.anchorFor(ctx, st, from)
	if err != nil {
		return err
	}
	cps, err := s.store.CheckpointsInRange(ctx, x.TenantID, x.ProjectID, st.ID, anchorSeq+1, to)
	if err != nil {
		return err
	}
	checkpoints := []integrity.Checkpoint{}
	if anchorCP != nil {
		checkpoints = append(checkpoints, anchorCP.Integrity())
	}
	for i := range cps {
		checkpoints = append(checkpoints, cps[i].Integrity())
	}
	publicKeys, err := s.store.PublicKeys(ctx, x.TenantID, x.ProjectID)
	if err != nil {
		return err
	}
	active, err := s.keys.EnsureActiveKey(ctx, x.TenantID, x.ProjectID)
	if err != nil {
		return err
	}
	signer, err := s.keys.Signer(ctx, active.ID)
	if err != nil {
		return err
	}
	report, _, err := s.verifier.VerifyStream(ctx, x.TenantID, x.ProjectID, st.Name, verification.StreamOptions{})
	if err != nil {
		return err
	}

	final, err := s.path(x)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), ".tmp-"+x.ID+"-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	created := s.now().UTC()
	b := evidence.NewBuilder(tmp, created)
	filters := p.Filters()
	chainEvents, err := b.WriteJSONL(evidence.FileChain, func(w *evidence.JSONLWriter) error {
		return s.page(ctx, x, st, anchorSeq+1, to, func(e store.Event) error {
			return w.Write(e.Record().WithoutContent())
		})
	})
	if err != nil {
		tmp.Close()
		return err
	}
	disclosed, err := b.WriteJSONL(evidence.FileEvents, func(w *evidence.JSONLWriter) error {
		return s.page(ctx, x, st, from, to, func(e store.Event) error {
			if !matches(e, p) {
				return nil
			}
			return w.Write(e.Record())
		})
	})
	if err != nil {
		tmp.Close()
		return err
	}
	if disclosed == 0 {
		tmp.Close()
		return ErrEmptySelection
	}
	steps := []func() error{
		func() error {
			return b.WriteJSON(evidence.FileCheckpoints, evidence.CheckpointsFile{Checkpoints: checkpoints})
		},
		func() error { return b.WriteJSON(evidence.FilePublicKeys, evidence.KeysFile{Keys: publicKeys}) },
		func() error { return b.WriteJSON(evidence.FileVerification, report) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			tmp.Close()
			return err
		}
	}
	manifest := evidence.Manifest{
		PackageID: x.ID, CreatedAt: integrity.FormatTime(created),
		Generator: evidence.Generator{Name: "delil", Version: s.version},
		Tenant:    evidence.NamedID{ID: tenant.ID, Name: tenant.Name},
		Project:   evidence.NamedID{ID: project.ID, Name: project.Name},
		Stream:    st.Name,
		Selection: evidence.Selection{FromSequence: from, ToSequence: to, Filters: filters, DisclosedEvents: disclosed},
		Chain: evidence.ChainInfo{FirstSequence: anchorSeq + 1, LastSequence: to, Events: chainEvents, Anchor: anchor,
			StreamHead: evidence.HeadSnapshot{Sequence: st.HeadSequence, Hash: st.HeadHashValue().String()}},
	}
	if p.From != nil {
		manifest.Selection.RecordedFrom = integrity.FormatTime(*p.From)
	}
	if p.To != nil {
		manifest.Selection.RecordedTo = integrity.FormatTime(*p.To)
	}
	if err := b.WriteFile(evidence.FileReadme, []byte(evidence.Readme(&manifest))); err != nil {
		tmp.Close()
		return err
	}
	mh, err := b.Finish(ctx, manifest, signer)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	sum, size, err := fileDigest(tmp.Name())
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return err
	}
	completed := s.now().UTC()
	expires := completed.Add(s.ttl)
	valid := report.Valid
	x.CompletedAt, x.ExpiresAt = &completed, &expires
	x.ChainEvents, x.DisclosedEvents = &chainEvents, &disclosed
	x.FirstSequence, x.LastSequence = &from, &to
	x.SizeBytes, x.SHA256, x.ManifestHash = &size, sum, mh[:]
	x.StoragePath = final
	x.VerificationValid = &valid
	return s.store.CompleteExport(ctx, x)
}

func matches(e store.Event, p Params) bool {
	idx := e.Index()
	return (p.ActorID == "" || idx.ActorID == p.ActorID) &&
		(p.Action == "" || idx.Action == p.Action) &&
		(p.ResourceType == "" || idx.ResourceType == p.ResourceType) &&
		(p.ResourceID == "" || idx.ResourceID == p.ResourceID)
}

// selectRange maps the parameters to a contiguous sequence range.
func (s *Service) selectRange(ctx context.Context, st store.Stream, p Params) (int64, int64, error) {
	if st.HeadSequence == 0 {
		return 0, 0, ErrEmptySelection
	}
	from, to := int64(1), st.HeadSequence
	switch {
	case p.From != nil || p.To != nil:
		lo, hi, ok, err := s.store.SequenceRangeForTime(ctx, st.TenantID, st.ProjectID, st.ID, p.From, p.To)
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			return 0, 0, ErrEmptySelection
		}
		from, to = lo, hi
	default:
		if p.FromSequence != nil {
			from = *p.FromSequence
		}
		if p.ToSequence != nil && *p.ToSequence < to {
			to = *p.ToSequence
		}
	}
	if from > to {
		return 0, 0, ErrEmptySelection
	}
	return from, to, nil
}

// anchorFor finds the newest checkpoint at or before from-1, or genesis.
func (s *Service) anchorFor(ctx context.Context, st store.Stream, from int64) (int64, evidence.ChainAnchor, *store.Checkpoint, error) {
	genesis := evidence.ChainAnchor{Type: evidence.AnchorGenesis, Sequence: 0, Hash: integrity.ZeroHash.String()}
	if from <= 1 {
		return 0, genesis, nil, nil
	}
	cp, err := s.store.LatestCheckpointAtOrBefore(ctx, st.TenantID, st.ProjectID, st.ID, from-1)
	if errors.Is(err, store.ErrNotFound) {
		return 0, genesis, nil, nil
	}
	if err != nil {
		return 0, genesis, nil, err
	}
	head := integrity.Hash{}
	copy(head[:], cp.HeadHash)
	return cp.Sequence, evidence.ChainAnchor{Type: evidence.AnchorCheckpoint, CheckpointID: cp.ID, Sequence: cp.Sequence,
		Hash: head.String()}, &cp, nil
}

func (s *Service) page(ctx context.Context, x store.Export, st store.Stream, from, to int64, fn func(store.Event) error) error {
	for next := from; next <= to; {
		rows, err := s.store.ChainRange(ctx, x.TenantID, x.ProjectID, st.ID, next, to, 2000)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, e := range rows {
			e.StreamName = st.Name
			if err := fn(e); err != nil {
				return err
			}
			next = e.Sequence + 1
		}
	}
	return nil
}

func fileDigest(path string) ([]byte, int64, error) {
	f, err := os.Open(path) //nolint:gosec // path is built by this package
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return h.Sum(nil), n, err
}

// Open returns the package of a completed export.
func (s *Service) Open(ctx context.Context, tenantID, projectID, exportID string) (*os.File, store.Export, error) {
	x, err := s.store.GetExport(ctx, tenantID, projectID, exportID)
	if err != nil {
		return nil, x, err
	}
	if x.Status != "completed" {
		return nil, x, ErrNotReady
	}
	path, err := s.path(x)
	if err != nil {
		return nil, x, err
	}
	f, err := os.Open(path) //nolint:gosec // path is built from validated identifiers
	return f, x, err
}

// Cleanup expires old exports and deletes their files.
func (s *Service) Cleanup(ctx context.Context) (int, error) {
	expired, err := s.store.ExpireExports(ctx, s.now())
	if err != nil {
		return 0, err
	}
	for _, x := range expired {
		if path, err := s.path(x); err == nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.log.Warn("removing expired export failed", "export_id", x.ID, "error", err)
			}
		}
	}
	return len(expired), nil
}
