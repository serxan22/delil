package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/serxan22/delil/internal/export"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

type createExportRequest struct {
	Stream       string `json:"stream"`
	From         string `json:"from"`
	To           string `json:"to"`
	FromSequence *int64 `json:"fromSequence"`
	ToSequence   *int64 `json:"toSequence"`
	ActorID      string `json:"actorId"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

func (s *Server) handleCreateExport(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req createExportRequest
	if err := decodeJSON(w, r, 64<<10, &req); err != nil {
		return err
	}
	params := export.Params{Stream: req.Stream, FromSequence: req.FromSequence, ToSequence: req.ToSequence,
		ActorID: req.ActorID, Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID}
	var err error
	if params.From, err = parseTimeParam(req.From, "from"); err != nil {
		return err
	}
	if params.To, err = parseTimeParam(req.To, "to"); err != nil {
		return err
	}
	x, err := s.exports.Create(r.Context(), p.TenantID, p.ProjectID, params, p.Actor())
	if errors.Is(err, store.ErrNotFound) {
		return notFound("stream")
	}
	if err != nil {
		return err
	}
	if s.metrics != nil {
		s.metrics.Exports.WithLabelValues("requested").Inc()
	}
	writeJSON(w, http.StatusAccepted, renderExport(x))
	return nil
}

func (s *Server) handleListExports(w http.ResponseWriter, r *http.Request, p *Principal) error {
	xs, err := s.store.ListExports(r.Context(), p.TenantID, p.ProjectID, 100)
	if err != nil {
		return err
	}
	views := make([]exportView, 0, len(xs))
	for _, x := range xs {
		views = append(views, renderExport(x))
	}
	writeJSON(w, http.StatusOK, list(views))
	return nil
}

func (s *Server) handleGetExport(w http.ResponseWriter, r *http.Request, p *Principal) error {
	exportID := r.PathValue("id")
	if !id.Valid(id.Export, exportID) {
		return notFound("export")
	}
	x, err := s.store.GetExport(r.Context(), p.TenantID, p.ProjectID, exportID)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("export")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, renderExport(x))
	return nil
}

func (s *Server) handleDownloadExport(w http.ResponseWriter, r *http.Request, p *Principal) error {
	exportID := r.PathValue("id")
	if !id.Valid(id.Export, exportID) {
		return notFound("export")
	}
	f, x, err := s.exports.Open(r.Context(), p.TenantID, p.ProjectID, exportID)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("export")
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	// The stream name and id are restricted to safe characters, so the file
	// name needs no further escaping.
	name := fmt.Sprintf("delil-evidence-%s-%s.zip", x.StreamName, x.ID)
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	if len(x.SHA256) > 0 {
		h.Set("Digest", "sha-256="+base64Std(x.SHA256))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		s.log.Warn("export download interrupted", "export_id", x.ID, "error", err)
	}
	return nil
}
