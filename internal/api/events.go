package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/store"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[\x21-\x7e]{1,255}$`)

func (s *Server) settingsFor(ctx context.Context, p *Principal) (audit.Settings, error) {
	project, err := s.store.GetProject(ctx, p.TenantID, p.ProjectID)
	if err != nil {
		return audit.Settings{}, err
	}
	return audit.ParseSettings(project.Settings)
}

func (s *Server) handleRecordEvent(w http.ResponseWriter, r *http.Request, p *Principal) error {
	return s.ingest(w, r, p, false)
}

func (s *Server) handleRecordBatch(w http.ResponseWriter, r *http.Request, p *Principal) error {
	return s.ingest(w, r, p, true)
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request, p *Principal, batch bool) error {
	start := time.Now()
	reject := func(reason string, err error) error {
		if s.metrics != nil {
			s.metrics.EventsRejected.WithLabelValues(reason).Inc()
		}
		return err
	}
	idemKey := r.Header.Get("Idempotency-Key")
	if idemKey != "" && !idempotencyKeyPattern.MatchString(idemKey) {
		return reject("bad_request", badRequest("Idempotency-Key must be 1-255 printable ASCII characters"))
	}
	limit := int64(s.cfg.MaxEventBytes) * 4
	if batch {
		limit = s.cfg.MaxRequestBytes
	}
	body, err := readBody(w, r, limit)
	if err != nil {
		return reject("bad_request", err)
	}
	tree, requestHash, err := audit.ParseRequestBody(body)
	if err != nil {
		return reject("invalid", err)
	}
	var inputs []audit.EventInput
	if batch {
		inputs, err = audit.DecodeBatch(tree, s.cfg.MaxBatchEvents)
	} else {
		var in audit.EventInput
		in, err = audit.DecodeEvent(tree)
		inputs = []audit.EventInput{in}
	}
	if err != nil {
		return reject("invalid", err)
	}
	settings, err := s.settingsFor(r.Context(), p)
	if err != nil {
		return err
	}
	prepared := make([]audit.Prepared, 0, len(inputs))
	for i, in := range inputs {
		pe, err := audit.Prepare(in, settings, s.cfg.MaxEventBytes)
		if err != nil {
			if batch && errors.Is(err, audit.ErrEventTooLarge) {
				return reject("too_large", errorf(http.StatusRequestEntityTooLarge, "event_too_large", "events[%d]: %v", i, err))
			}
			return reject("too_large", err)
		}
		prepared = append(prepared, pe)
	}
	endpoint := "POST /v1/events"
	if batch {
		endpoint = "POST /v1/events/batch"
	}
	res, err := s.appender.Append(r.Context(), audit.AppendRequest{
		TenantID: p.TenantID, ProjectID: p.ProjectID, Events: prepared,
		IdempotencyKey: idemKey, RequestHash: requestHash, Endpoint: endpoint,
	})
	if err != nil {
		return reject("error", err)
	}
	if s.metrics != nil {
		s.metrics.IngestDuration.Observe(time.Since(start).Seconds())
		if !res.Replayed {
			s.metrics.EventsIngested.Add(float64(len(res.Events)))
		}
	}
	if res.Replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	receipts := make([]receiptView, len(res.Events))
	for i, c := range res.Events {
		receipts[i] = receipt(c.Record)
	}
	if batch {
		writeJSON(w, http.StatusCreated, list(receipts))
	} else {
		writeJSON(w, http.StatusCreated, receipts[0])
	}
	return nil
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request, p *Principal) error {
	eventID := r.PathValue("id")
	if !id.Valid(id.Event, eventID) {
		return notFound("event")
	}
	e, err := s.store.GetEvent(r.Context(), p.TenantID, p.ProjectID, eventID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("event")
		}
		return err
	}
	v := renderEvent(e)
	sv, err := s.store.LatestStreamVerification(r.Context(), p.ProjectID, e.StreamID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err == nil {
		v.Verification = eventStatus(e, &sv)
	} else {
		v.Verification = eventStatus(e, nil)
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

// Cursors are opaque to clients: base64url("<unix micros>|<event id>").
func encodeCursor(e store.Event) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(e.RecordedAt.UnixMicro(), 10) + "|" + e.ID))
}

func decodeCursor(c string) (*time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, "", badRequest("invalid cursor")
	}
	micros, eventID, ok := strings.Cut(string(raw), "|")
	n, err := strconv.ParseInt(micros, 10, 64)
	if !ok || err != nil || !id.Valid(id.Event, eventID) {
		return nil, "", badRequest("invalid cursor")
	}
	t := time.UnixMicro(n).UTC()
	return &t, eventID, nil
}

func parseTimeParam(q string, name string) (*time.Time, error) {
	if q == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, q); err == nil {
			u := t.UTC()
			return &u, nil
		}
	}
	return nil, badRequest("%s must be an RFC 3339 timestamp or a date (YYYY-MM-DD)", name)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, p *Principal) error {
	q := r.URL.Query()
	f := store.EventFilter{TenantID: p.TenantID, ProjectID: p.ProjectID, Stream: q.Get("stream"),
		ActorID: q.Get("actorId"), ActorType: q.Get("actorType"), Action: q.Get("action"),
		ResourceType: q.Get("resourceType"), ResourceID: q.Get("resourceId"), Status: q.Get("verificationStatus")}
	switch f.Status {
	case "", "verified", "failed", "unverified":
	default:
		return badRequest("verificationStatus must be verified, failed or unverified")
	}
	var err error
	if f.From, err = parseTimeParam(q.Get("from"), "from"); err != nil {
		return err
	}
	if f.To, err = parseTimeParam(q.Get("to"), "to"); err != nil {
		return err
	}
	limit := 50
	if l := q.Get("limit"); l != "" {
		if limit, err = strconv.Atoi(l); err != nil || limit < 1 || limit > 200 {
			return badRequest("limit must be between 1 and 200")
		}
	}
	if c := q.Get("cursor"); c != "" {
		if f.CursorTime, f.CursorID, err = decodeCursor(c); err != nil {
			return err
		}
	}
	f.Limit = limit + 1
	events, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		return err
	}
	out := list([]eventView{})
	if len(events) > limit {
		events = events[:limit]
		out.HasMore = true
		out.NextCursor = encodeCursor(events[len(events)-1])
	}
	cache := map[string]*store.StreamVerification{}
	for _, e := range events {
		sv, ok := cache[e.StreamID]
		if !ok {
			v, err := s.store.LatestStreamVerification(r.Context(), p.ProjectID, e.StreamID)
			if err == nil {
				sv = &v
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			cache[e.StreamID] = sv
		}
		view := renderEvent(e)
		view.Verification = eventStatus(e, sv)
		out.Data = append(out.Data, view)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleVerifyEvent(w http.ResponseWriter, r *http.Request, p *Principal) error {
	eventID := r.PathValue("id")
	if !id.Valid(id.Event, eventID) {
		return notFound("event")
	}
	rep, _, err := s.verifier.VerifyEvent(r.Context(), p.TenantID, p.ProjectID, eventID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("event")
		}
		return err
	}
	s.countVerification("event", rep.Valid)
	writeJSON(w, http.StatusOK, rep)
	return nil
}

func (s *Server) countVerification(scope string, valid bool) {
	if s.metrics == nil {
		return
	}
	result := "valid"
	if !valid {
		result = "invalid"
		s.metrics.VerificationFailures.WithLabelValues(scope).Inc()
	}
	s.metrics.Verifications.WithLabelValues(scope, result).Inc()
}
