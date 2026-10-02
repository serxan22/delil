package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/serxan22/delil/internal/checkpoint"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/internal/verification"
	"github.com/serxan22/delil/pkg/integrity"
)

func (s *Server) stream(r *http.Request, p *Principal) (store.Stream, error) {
	name := r.PathValue("name")
	if !integrity.ValidStreamName(name) {
		return store.Stream{}, notFound("stream")
	}
	st, err := s.store.GetStream(r.Context(), p.TenantID, p.ProjectID, name)
	if errors.Is(err, store.ErrNotFound) {
		return st, notFound("stream")
	}
	return st, err
}

func (s *Server) handleListStreams(w http.ResponseWriter, r *http.Request, p *Principal) error {
	streams, err := s.store.ListStreams(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	views := make([]streamView, 0, len(streams))
	for _, st := range streams {
		views = append(views, renderStream(st.Stream, st.LastVerification))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

func (s *Server) handleGetStream(w http.ResponseWriter, r *http.Request, p *Principal) error {
	st, err := s.stream(r, p)
	if err != nil {
		return err
	}
	var latest *store.StreamVerification
	sv, err := s.store.LatestStreamVerification(r.Context(), p.ProjectID, st.ID)
	if err == nil {
		latest = &sv
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	writeJSON(w, http.StatusOK, renderStream(st, latest))
	return nil
}

type chainView struct {
	Object            string             `json:"object"`
	Stream            string             `json:"stream"`
	TenantID          string             `json:"tenantId"`
	ProjectID         string             `json:"projectId"`
	Records           []integrity.Record `json:"records"`
	HasMore           bool               `json:"hasMore"`
	NextAfterSequence int64              `json:"nextAfterSequence"`
	Head              headView           `json:"head"`
}

type headView struct {
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

// handleChain serves raw chain records (headers, hashes, signatures and the
// exact canonical content) so clients can verify independently.
func (s *Server) handleChain(w http.ResponseWriter, r *http.Request, p *Principal) error {
	st, err := s.stream(r, p)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	after := int64(0)
	if v := q.Get("afterSequence"); v != "" {
		if after, err = strconv.ParseInt(v, 10, 64); err != nil || after < 0 {
			return badRequest("afterSequence must be a non-negative integer")
		}
	}
	limit := 1000
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > 5000 {
			return badRequest("limit must be between 1 and 5000")
		}
	}
	withContent := q.Get("content") != "false"
	rows, err := s.store.ChainPage(r.Context(), p.TenantID, p.ProjectID, st.ID, after, limit+1)
	if err != nil {
		return err
	}
	out := chainView{Object: "chain", Stream: st.Name, TenantID: st.TenantID, ProjectID: st.ProjectID,
		Records: []integrity.Record{}, Head: headView{Sequence: st.HeadSequence, Hash: st.HeadHashValue().String()},
		NextAfterSequence: after}
	if len(rows) > limit {
		rows = rows[:limit]
		out.HasMore = true
	}
	for _, e := range rows {
		e.StreamName = st.Name
		rec := e.Record()
		if !withContent {
			rec = rec.WithoutContent()
		}
		out.Records = append(out.Records, rec)
		out.NextAfterSequence = e.Sequence
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

type verifyStreamRequest struct {
	Witnesses []integrity.Checkpoint `json:"witnesses"`
}

func (s *Server) handleVerifyStream(w http.ResponseWriter, r *http.Request, p *Principal) error {
	st, err := s.stream(r, p)
	if err != nil {
		return err
	}
	var req verifyStreamRequest
	if r.ContentLength != 0 && r.Header.Get("Content-Type") != "" {
		if err := decodeJSON(w, r, 1<<20, &req); err != nil {
			return err
		}
	}
	rep, st, err := s.verifier.VerifyStream(r.Context(), p.TenantID, p.ProjectID, st.Name,
		verification.StreamOptions{Witnesses: req.Witnesses})
	if err != nil {
		return err
	}
	run, err := s.verifier.RecordStream(r.Context(), p.TenantID, p.ProjectID, st, rep, trigger(r, p))
	if err != nil {
		return err
	}
	s.countVerification("stream", rep.Valid)
	writeJSON(w, http.StatusOK, renderRun(run))
	return nil
}

func (s *Server) handleListCheckpoints(w http.ResponseWriter, r *http.Request, p *Principal) error {
	st, err := s.stream(r, p)
	if err != nil {
		return err
	}
	cps, err := s.store.ListCheckpoints(r.Context(), p.TenantID, p.ProjectID, st.ID)
	if err != nil {
		return err
	}
	views := make([]checkpointView, 0, len(cps))
	for i := range cps {
		views = append(views, checkpointView{Object: "checkpoint", Checkpoint: cps[i].Integrity()})
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

func (s *Server) handleCreateCheckpoint(w http.ResponseWriter, r *http.Request, p *Principal) error {
	st, err := s.stream(r, p)
	if err != nil {
		return err
	}
	cp, created, err := s.checkpoints.CreateForStream(r.Context(), st)
	if errors.Is(err, checkpoint.ErrEmptyStream) {
		return errorf(http.StatusConflict, "empty_stream", "the stream has no events to checkpoint")
	}
	if err != nil {
		return err
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		if s.metrics != nil {
			s.metrics.CheckpointsCreated.Inc()
		}
	}
	writeJSON(w, status, checkpointView{Object: "checkpoint", Checkpoint: cp.Integrity()})
	return nil
}

func (s *Server) handleVerifyProject(w http.ResponseWriter, r *http.Request, p *Principal) error {
	pr, err := s.verifier.VerifyProject(r.Context(), p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	run, err := s.verifier.RecordProject(r.Context(), p.TenantID, p.ProjectID, pr, trigger(r, p))
	if err != nil {
		return err
	}
	s.countVerification("project", pr.Valid)
	writeJSON(w, http.StatusOK, renderRun(run))
	return nil
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request, p *Principal) error {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return badRequest("limit must be between 1 and 200")
		}
		limit = n
	}
	runs, err := s.store.ListVerificationRuns(r.Context(), p.TenantID, p.ProjectID, limit)
	if err != nil {
		return err
	}
	views := make([]runView, 0, len(runs))
	for _, run := range runs {
		views = append(views, renderRun(run))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request, p *Principal) error {
	runID := r.PathValue("id")
	if !id.Valid(id.Verification, runID) {
		return notFound("verification run")
	}
	run, err := s.store.GetVerificationRun(r.Context(), p.TenantID, p.ProjectID, runID)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("verification run")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, renderRun(run))
	return nil
}
