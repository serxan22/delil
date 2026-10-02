package api

import (
	"errors"
	"net/http"

	"github.com/serxan22/delil/internal/store"
)

type overviewView struct {
	Object       string          `json:"object"`
	Project      projectView     `json:"project"`
	Stats        statsView       `json:"stats"`
	Verification healthView      `json:"verification"`
	EventsPerDay []dayView       `json:"eventsPerDay"`
	RecentEvents []eventView     `json:"recentEvents"`
	SigningKey   *signingKeyView `json:"signingKey,omitempty"`
}

type statsView struct {
	EventsTotal   int64   `json:"eventsTotal"`
	EventsToday   int64   `json:"eventsToday"`
	Streams       int     `json:"streams"`
	ActiveStreams int     `json:"activeStreams"`
	LastEventAt   *string `json:"lastEventAt,omitempty"`
}

type healthView struct {
	// Status is "healthy" when every stream passed its latest verification,
	// "failing" if any failed, "unverified" when streams were never verified
	// or have events newer than their latest verification.
	Status            string   `json:"status"`
	StreamsPassing    int      `json:"streamsPassing"`
	StreamsFailing    int      `json:"streamsFailing"`
	StreamsUnverified int      `json:"streamsUnverified"`
	LatestRun         *runView `json:"latestRun,omitempty"`
}

type dayView struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, p *Principal) error {
	ctx := r.Context()
	now := s.now().UTC()
	pr, err := s.store.GetProject(ctx, p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	stats, err := s.store.GetProjectStats(ctx, p.TenantID, p.ProjectID, now)
	if err != nil {
		return err
	}
	streams, err := s.store.ListStreams(ctx, p.TenantID, p.ProjectID)
	if err != nil {
		return err
	}
	health := healthView{}
	for _, st := range streams {
		lv := st.LastVerification
		switch {
		case st.HeadSequence == 0:
		case lv == nil:
			health.StreamsUnverified++
		case !lv.Valid:
			health.StreamsFailing++
		case lv.LastSequence == nil || *lv.LastSequence < st.HeadSequence:
			health.StreamsUnverified++
		default:
			health.StreamsPassing++
		}
	}
	switch {
	case health.StreamsFailing > 0:
		health.Status = "failing"
	case health.StreamsUnverified > 0:
		health.Status = "unverified"
	default:
		health.Status = "healthy"
	}
	if run, err := s.store.LatestVerificationRun(ctx, p.TenantID, p.ProjectID); err == nil {
		v := renderRun(run)
		health.LatestRun = &v
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	days, err := s.store.EventsPerDay(ctx, p.TenantID, p.ProjectID, now, 14)
	if err != nil {
		return err
	}
	recent, err := s.store.ListEvents(ctx, store.EventFilter{TenantID: p.TenantID, ProjectID: p.ProjectID, Limit: 8})
	if err != nil {
		return err
	}
	out := overviewView{
		Object:  "overview",
		Project: renderProject(pr, nil),
		Stats: statsView{EventsTotal: stats.EventsTotal, EventsToday: stats.EventsToday, Streams: stats.Streams,
			ActiveStreams: stats.ActiveStreams, LastEventAt: tsPtr(stats.LastEventAt)},
		Verification: health,
		EventsPerDay: make([]dayView, 0, len(days)),
		RecentEvents: make([]eventView, 0, len(recent)),
	}
	for _, d := range days {
		out.EventsPerDay = append(out.EventsPerDay, dayView{Date: d.Day.Format("2006-01-02"), Count: d.Count})
	}
	verifications := map[string]*store.StreamVerification{}
	for _, st := range streams {
		verifications[st.ID] = st.LastVerification
	}
	for _, e := range recent {
		v := renderEvent(e)
		v.Verification = eventStatus(e, verifications[e.StreamID])
		out.RecentEvents = append(out.RecentEvents, v)
	}
	if k, err := s.store.GetActiveSigningKey(ctx, p.TenantID, p.ProjectID); err == nil {
		v := renderSigningKey(k)
		out.SigningKey = &v
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
