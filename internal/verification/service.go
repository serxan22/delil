// Package verification runs pkg/verify against the database and records the
// results as verification runs.
package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/keys"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

// PageSize is how many events are read per database round trip.
const PageSize = 2000

// Service verifies streams, events and projects stored in PostgreSQL.
type Service struct {
	store    *store.Store
	keys     *keys.Manager
	verifier verify.VerifierInfo
	now      func() time.Time
}

// NewService returns a Service. version identifies the running build.
func NewService(st *store.Store, km *keys.Manager, version string) *Service {
	return &Service{store: st, keys: km, now: time.Now,
		verifier: verify.VerifierInfo{Name: "delil-server", Version: version, Location: "server"}}
}

// dbSource pages through a stream in sequence order.
type dbSource struct {
	store                 *store.Store
	tenant, project, strm string
	streamName            string
	after                 int64
	done                  bool
}

func (s *dbSource) Next(ctx context.Context) ([]verify.Item, error) {
	if s.done {
		return nil, nil
	}
	rows, err := s.store.ChainPage(ctx, s.tenant, s.project, s.strm, s.after, PageSize)
	if err != nil {
		return nil, err
	}
	if len(rows) < PageSize {
		s.done = true
	}
	items := make([]verify.Item, len(rows))
	for i := range rows {
		// The verified stream's name is used, not anything stored on the row.
		rows[i].StreamName = s.streamName
		idx := rows[i].Index()
		items[i] = verify.Item{Record: rows[i].Record(), Index: &idx}
		s.after = rows[i].Sequence
	}
	return items, nil
}

// StreamOptions add optional inputs to a stream verification.
type StreamOptions struct {
	Witnesses []integrity.Checkpoint
}

// VerifyStream verifies a whole stream from genesis, including its head and
// every stored checkpoint.
func (s *Service) VerifyStream(ctx context.Context, tenantID, projectID, streamName string, opts StreamOptions) (*verify.Report, store.Stream, error) {
	st, err := s.store.GetStream(ctx, tenantID, projectID, streamName)
	if err != nil {
		return nil, st, err
	}
	keySet, rejected, err := s.keys.KeySet(ctx, tenantID, projectID)
	if err != nil {
		return nil, st, err
	}
	cps, err := s.store.ListCheckpoints(ctx, tenantID, projectID, st.ID)
	if err != nil {
		return nil, st, err
	}
	checkpoints := make([]integrity.Checkpoint, len(cps))
	for i := range cps {
		checkpoints[i] = cps[i].Integrity()
	}
	rep, err := verify.VerifyStream(ctx, &dbSource{store: s.store, tenant: tenantID, project: projectID,
		strm: st.ID, streamName: st.Name}, verify.StreamOptions{
		TenantID:                tenantID,
		ProjectID:               projectID,
		Stream:                  st.Name,
		Keys:                    keySet,
		KeySource:               "server database",
		RejectedKeys:            rejected,
		Head:                    &verify.Head{Sequence: st.HeadSequence, Hash: st.HeadHashValue()},
		Checkpoints:             checkpoints,
		Witnesses:               opts.Witnesses,
		RequireContent:          true,
		RequireCanonicalContent: true,
		Verifier:                &s.verifier,
	})
	return rep, st, err
}

// VerifyEvent verifies one event and its links to its neighbours.
func (s *Service) VerifyEvent(ctx context.Context, tenantID, projectID, eventID string) (*verify.Report, store.Event, error) {
	ev, err := s.store.GetEvent(ctx, tenantID, projectID, eventID)
	if err != nil {
		return nil, ev, err
	}
	keySet, rejected, err := s.keys.KeySet(ctx, tenantID, projectID)
	if err != nil {
		return nil, ev, err
	}
	st, err := s.store.GetStreamByID(ctx, tenantID, projectID, ev.StreamID)
	if err != nil {
		return nil, ev, err
	}
	toItem := func(e store.Event) *verify.Item {
		e.StreamName = st.Name
		idx := e.Index()
		return &verify.Item{Record: e.Record(), Index: &idx}
	}
	var prev, next *verify.Item
	if ev.Sequence > 1 {
		p, err := s.store.GetEventBySequence(ctx, tenantID, projectID, st.ID, ev.Sequence-1)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, ev, err
		}
		if err == nil {
			prev = toItem(p)
		}
	}
	n, err := s.store.GetEventBySequence(ctx, tenantID, projectID, st.ID, ev.Sequence+1)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, ev, err
	}
	if err == nil {
		next = toItem(n)
	}
	var head *verify.Head
	if next == nil {
		head = &verify.Head{Sequence: st.HeadSequence, Hash: st.HeadHashValue()}
	}
	rep := verify.VerifyEvent(*toItem(ev), prev, next, verify.EventOptions{
		TenantID: tenantID, ProjectID: projectID, Stream: st.Name, Keys: keySet, KeySource: "server database",
		RejectedKeys: rejected, RequireCanonicalContent: true, Verifier: &s.verifier, Head: head,
	})
	return rep, ev, nil
}

// ProjectReport aggregates stream reports.
type ProjectReport struct {
	Object            string           `json:"object"`
	Scope             string           `json:"scope"`
	Result            string           `json:"result"`
	Valid             bool             `json:"valid"`
	TamperingDetected bool             `json:"tamperingDetected"`
	ProjectID         string           `json:"projectId"`
	StreamsChecked    int              `json:"streamsChecked"`
	EventsChecked     int64            `json:"eventsChecked"`
	FailureCount      int              `json:"failureCount"`
	Streams           []*verify.Report `json:"streams"`
	StartedAt         string           `json:"startedAt"`
	CompletedAt       string           `json:"completedAt"`
	DurationMs        int64            `json:"durationMs"`
}

// VerifyProject verifies every stream of the project.
func (s *Service) VerifyProject(ctx context.Context, tenantID, projectID string) (*ProjectReport, error) {
	start := s.now()
	streams, err := s.store.ListStreams(ctx, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	pr := &ProjectReport{Object: "project_verification_report", Scope: "project", ProjectID: projectID,
		Streams: []*verify.Report{}}
	for _, st := range streams {
		rep, _, err := s.VerifyStream(ctx, tenantID, projectID, st.Name, StreamOptions{})
		if err != nil {
			return nil, fmt.Errorf("verify stream %s: %w", st.Name, err)
		}
		pr.Streams = append(pr.Streams, rep)
		pr.StreamsChecked++
		pr.EventsChecked += rep.EventsChecked
		pr.FailureCount += rep.FailureCount
	}
	pr.Valid = pr.FailureCount == 0
	pr.TamperingDetected = !pr.Valid
	pr.Result = verify.ResultValid
	if !pr.Valid {
		pr.Result = verify.ResultInvalid
	}
	end := s.now()
	pr.StartedAt, pr.CompletedAt = integrity.FormatTime(start), integrity.FormatTime(end)
	pr.DurationMs = end.Sub(start).Milliseconds()
	return pr, nil
}

// Trigger describes who started a run.
type Trigger struct {
	Kind string // api, dashboard, schedule, cli, system
	By   string
}

// RecordStream stores a stream report as a verification run.
func (s *Service) RecordStream(ctx context.Context, tenantID, projectID string, st store.Stream, rep *verify.Report, trig Trigger) (store.VerificationRun, error) {
	return s.record(ctx, tenantID, projectID, "stream", st.Name, []streamReport{{st.ID, rep}}, rep, trig)
}

// RecordProject stores a project report as a verification run.
func (s *Service) RecordProject(ctx context.Context, tenantID, projectID string, pr *ProjectReport, trig Trigger) (store.VerificationRun, error) {
	streams, err := s.store.ListStreams(ctx, tenantID, projectID)
	if err != nil {
		return store.VerificationRun{}, err
	}
	ids := map[string]string{}
	for _, st := range streams {
		ids[st.Name] = st.ID
	}
	var srs []streamReport
	for _, rep := range pr.Streams {
		if sid, ok := ids[rep.Stream]; ok {
			srs = append(srs, streamReport{sid, rep})
		}
	}
	return s.record(ctx, tenantID, projectID, "project", "", srs, pr, trig)
}

// RecordEvent stores an event report as a verification run (no per-stream row:
// an event check does not establish the state of the whole stream).
func (s *Service) RecordEvent(ctx context.Context, tenantID, projectID string, rep *verify.Report, trig Trigger) (store.VerificationRun, error) {
	return s.record(ctx, tenantID, projectID, "event", rep.EventID, nil, rep, trig)
}

type streamReport struct {
	streamID string
	report   *verify.Report
}

func (s *Service) record(ctx context.Context, tenantID, projectID, scope, target string, streams []streamReport, report any, trig Trigger) (store.VerificationRun, error) {
	started := s.now().UTC()
	run := store.VerificationRun{ID: id.New(id.Verification), TenantID: tenantID, ProjectID: projectID, Scope: scope,
		Target: target, Trigger: trig.Kind, TriggeredBy: trig.By, StartedAt: started}
	raw, err := json.Marshal(report)
	if err != nil {
		return run, err
	}
	var svs []store.StreamVerification
	for _, sr := range streams {
		rep := sr.report
		sv := store.StreamVerification{StreamID: sr.streamID, ProjectID: projectID, Valid: rep.Valid,
			EventsChecked: rep.EventsChecked, FailureCount: rep.FailureCount, CompletedAt: started}
		if rep.EventsChecked > 0 {
			first, last := rep.FirstSequence, rep.LastSequence
			sv.FirstSequence, sv.LastSequence = &first, &last
		}
		if rep.FirstFailure != nil {
			ff := rep.FirstFailure.Sequence
			if ff > 0 {
				sv.FirstFailureSequence = &ff
			}
			sv.FirstFailure, _ = json.Marshal(rep.FirstFailure)
		}
		seen := map[int64]bool{}
		for _, f := range rep.Failures {
			if f.Sequence > 0 && !seen[f.Sequence] {
				seen[f.Sequence] = true
				sv.FailureSequences = append(sv.FailureSequences, f.Sequence)
			}
		}
		svs = append(svs, sv)
		run.StreamsChecked++
		run.EventsChecked += rep.EventsChecked
		run.FailureCount += rep.FailureCount
	}
	if scope == "event" {
		if rep, ok := report.(*verify.Report); ok {
			run.EventsChecked, run.FailureCount = rep.EventsChecked, rep.FailureCount
		}
	}
	run.Status = "passed"
	if run.FailureCount > 0 {
		run.Status = "failed"
	}
	run.Report = raw
	completed := s.now().UTC()
	run.CompletedAt = &completed
	if err := s.store.CreateVerificationRun(ctx, run); err != nil {
		return run, err
	}
	if err := s.store.CompleteVerificationRun(ctx, run, svs); err != nil {
		return run, err
	}
	return run, nil
}
