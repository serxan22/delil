// Package metrics defines DƏLİL's Prometheus metrics. Labels never contain
// event contents, actor or resource identifiers; route labels are route
// patterns, not raw paths, so cardinality stays bounded.
package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics groups every collector.
type Metrics struct {
	Registry             *prometheus.Registry
	EventsIngested       prometheus.Counter
	EventsRejected       *prometheus.CounterVec
	IngestDuration       prometheus.Histogram
	Verifications        *prometheus.CounterVec
	VerificationFailures *prometheus.CounterVec
	APIRequests          *prometheus.CounterVec
	APIDuration          *prometheus.HistogramVec
	CheckpointsCreated   prometheus.Counter
	Exports              *prometheus.CounterVec
}

// StreamHeadSource lists stream heads for the delil_stream_head_sequence gauge.
type StreamHeadSource interface {
	StreamHeads(ctx context.Context, limit int) ([]StreamHead, error)
}

// StreamHead is one gauge sample.
type StreamHead struct {
	ProjectID string
	Stream    string
	Sequence  int64
}

// New registers all metrics. heads may be nil.
func New(version string, heads StreamHeadSource) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		EventsIngested: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "delil_events_ingested_total", Help: "Events committed to audit streams."}),
		EventsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "delil_events_rejected_total", Help: "Ingestion requests rejected, by reason."}, []string{"reason"}),
		IngestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "delil_event_ingest_duration_seconds", Help: "Time to validate, sign and commit an ingestion request.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5}}),
		Verifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "delil_verifications_total", Help: "Verifications performed, by scope and result."}, []string{"scope", "result"}),
		VerificationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "delil_verification_failures_total", Help: "Verifications that detected integrity failures, by scope."}, []string{"scope"}),
		APIRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "delil_api_requests_total", Help: "HTTP requests by method, route pattern and status."}, []string{"method", "route", "status"}),
		APIDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "delil_api_request_duration_seconds", Help: "HTTP request latency by route pattern.",
			Buckets: prometheus.DefBuckets}, []string{"method", "route"}),
		CheckpointsCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "delil_checkpoints_created_total", Help: "Signed checkpoints created."}),
		Exports: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "delil_exports_total", Help: "Evidence exports requested."}, []string{"result"}),
	}
	reg.MustRegister(m.EventsIngested, m.EventsRejected, m.IngestDuration, m.Verifications, m.VerificationFailures,
		m.APIRequests, m.APIDuration, m.CheckpointsCreated, m.Exports,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "delil_build_info", Help: "Build information.",
			ConstLabels: prometheus.Labels{"version": version}}, func() float64 { return 1 }))
	if heads != nil {
		reg.MustRegister(&headCollector{src: heads})
	}
	return m
}

var headDesc = prometheus.NewDesc("delil_stream_head_sequence",
	"Head sequence of each audit stream (first 1000 streams).", []string{"project_id", "stream"}, nil)

type headCollector struct {
	src StreamHeadSource
}

func (c *headCollector) Describe(ch chan<- *prometheus.Desc) { ch <- headDesc }

func (c *headCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	heads, err := c.src.StreamHeads(ctx, 1000)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(headDesc, err)
		return
	}
	for _, h := range heads {
		ch <- prometheus.MustNewConstMetric(headDesc, prometheus.GaugeValue, float64(h.Sequence), h.ProjectID, h.Stream)
	}
}
