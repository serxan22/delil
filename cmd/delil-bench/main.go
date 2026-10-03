// Command delil-bench measures DƏLİL's throughput.
//
// Engine mode (the default) needs nothing but this binary: it canonicalizes,
// hashes, links and signs N events in memory, verifies the resulting chain
// with pkg/verify, then tampers with one event and checks that verification
// pinpoints it.
//
//	go run ./cmd/delil-bench -events 100000
//
// HTTP mode load-tests a running server through the public API, then verifies
// every stream it wrote locally (downloading the raw chain, exactly like
// `delil verify`) and on the server:
//
//	DELIL_API_KEY=dlk_... go run ./cmd/delil-bench -url http://localhost:8080 \
//	    -events 20000 -concurrency 8 -batch 50 -streams 4
//
// The API rate limit (DELIL_RATE_LIMIT_RPS, 100 req/s per key by default)
// bounds HTTP-mode throughput; raise it on a benchmark server. Rate-limited
// requests are retried with the same idempotency key and counted.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/serxan22/delil/internal/audit"
	"github.com/serxan22/delil/internal/id"
	"github.com/serxan22/delil/internal/version"
	"github.com/serxan22/delil/pkg/client"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

type options struct {
	url         string
	apiKey      string
	events      int
	concurrency int
	batch       int
	streams     int
	prefix      string
	jsonOut     bool
}

func main() {
	o := options{}
	flag.StringVar(&o.url, "url", "", "server base URL; empty runs the offline engine benchmark")
	flag.StringVar(&o.apiKey, "api-key", "", "API key with events:write and events:read (default $DELIL_API_KEY)")
	flag.IntVar(&o.events, "events", 0, "number of events (default 100000 engine, 10000 http)")
	flag.IntVar(&o.concurrency, "concurrency", 8, "concurrent HTTP workers")
	flag.IntVar(&o.batch, "batch", 50, "events per HTTP request (1 uses POST /v1/events)")
	flag.IntVar(&o.streams, "streams", 4, "streams to spread HTTP load over")
	flag.StringVar(&o.prefix, "stream-prefix", "", "stream name prefix (default bench-<time>)")
	flag.BoolVar(&o.jsonOut, "json", false, "print the result as JSON")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var res any
	var err error
	if o.url == "" {
		if o.events == 0 {
			o.events = 100_000
		}
		res, err = runEngine(ctx, o)
	} else {
		if o.events == 0 {
			o.events = 10_000
		}
		if o.apiKey == "" {
			o.apiKey = os.Getenv("DELIL_API_KEY")
		}
		res, err = runHTTP(ctx, o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "delil-bench:", err)
		os.Exit(1)
	}
	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	}
}

// ---------------------------------------------------------------------------
// Engine mode

type engineResult struct {
	Mode            string  `json:"mode"`
	Version         string  `json:"version"`
	GoVersion       string  `json:"goVersion"`
	CPUs            int     `json:"cpus"`
	Events          int     `json:"events"`
	AvgContentBytes int     `json:"avgContentBytes"`
	PrepareMs       int64   `json:"prepareMs"`
	SealMs          int64   `json:"sealMs"`
	VerifyMs        int64   `json:"verifyMs"`
	PreparePerSec   float64 `json:"preparePerSec"`
	SealPerSec      float64 `json:"sealPerSec"`
	VerifyPerSec    float64 `json:"verifyPerSec"`
	TamperDetected  bool    `json:"tamperDetected"`
	TamperSequence  int64   `json:"tamperSequence"`
	TamperReason    string  `json:"tamperReason"`
}

func sampleInput(i int) audit.EventInput {
	occurred := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second)
	return audit.EventInput{
		Stream:     "bench",
		Actor:      integrity.Actor{Type: "user", ID: fmt.Sprintf("user_%d", i%97), DisplayName: "Bench User"},
		Action:     "contract.updated",
		Resource:   &integrity.Resource{Type: "contract", ID: fmt.Sprintf("contract_%d", i%1009)},
		Before:     map[string]any{"status": "draft", "amount": float64(i % 5000), "currency": "AZN"},
		HasBefore:  true,
		After:      map[string]any{"status": "pending", "amount": float64(i%5000 + 10), "currency": "AZN"},
		HasAfter:   true,
		Metadata:   map[string]any{"requestId": fmt.Sprintf("req_%08d", i)},
		Context:    &integrity.RequestContext{RequestID: fmt.Sprintf("req_%08d", i), SourceIP: "203.0.113.7"},
		OccurredAt: &occurred,
	}
}

func runEngine(ctx context.Context, o options) (*engineResult, error) {
	if o.events < 2 {
		return nil, errors.New("-events must be at least 2")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := integrity.NewEd25519Signer(priv)
	if err != nil {
		return nil, err
	}
	keys, err := integrity.NewKeySet(integrity.NewPublicKey(signer.PublicKey()))
	if err != nil {
		return nil, err
	}
	res := &engineResult{Mode: "engine", Version: version.Version, GoVersion: runtime.Version(),
		CPUs: runtime.NumCPU(), Events: o.events}
	fmt.Printf("DƏLİL engine benchmark · %s events · %d CPUs · %s\n", verify.Thousands(int64(o.events)), res.CPUs, res.GoVersion)

	// 1. Validate, diff and canonicalize (RFC 8785).
	start := time.Now()
	prepared := make([]audit.Prepared, o.events)
	total := 0
	for i := range prepared {
		p, err := audit.Prepare(sampleInput(i), audit.DefaultSettings(), 256*1024)
		if err != nil {
			return nil, err
		}
		prepared[i] = p
		total += len(p.Content)
	}
	res.PrepareMs, res.PreparePerSec = rate(o.events, time.Since(start))
	res.AvgContentBytes = total / o.events
	fmt.Printf("  canonicalize  %8d ms  %12s events/s  (avg %d bytes)\n", res.PrepareMs, perSec(res.PreparePerSec), res.AvgContentBytes)

	// 2. Hash, link and sign: the appender's critical section without I/O.
	start = time.Now()
	const tenant, project = "org_01JBENCH0000000000000000000", "prj_01JBENCH0000000000000000000"
	items := make([]verify.Item, o.events)
	prev := integrity.ZeroHash
	recorded := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for i := range prepared {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rec, err := integrity.Seal(ctx, integrity.SealInput{
			TenantID: tenant, ProjectID: project, Stream: "bench", Sequence: int64(i + 1),
			EventID: id.New(id.Event), RecordedAt: recorded.Add(time.Duration(i) * time.Millisecond),
			PreviousHash: prev, CanonicalContent: prepared[i].Content,
		}, signer)
		if err != nil {
			return nil, err
		}
		items[i] = verify.Item{Record: rec}
		prev = rec.EventHash
	}
	res.SealMs, res.SealPerSec = rate(o.events, time.Since(start))
	fmt.Printf("  hash+sign     %8d ms  %12s events/s\n", res.SealMs, perSec(res.SealPerSec))

	opts := verify.StreamOptions{TenantID: tenant, ProjectID: project, Stream: "bench", Keys: keys,
		KeySource: "benchmark", Head: &verify.Head{Sequence: int64(o.events), Hash: prev},
		RequireContent: true, RequireCanonicalContent: true}

	// 3. Full verification: payload hashes, header hashes, links, signatures.
	start = time.Now()
	rep, err := verify.VerifyStream(ctx, &verify.SliceSource{Items: items, BatchSize: 2000}, opts)
	if err != nil {
		return nil, err
	}
	if !rep.Valid {
		return nil, fmt.Errorf("untampered chain failed verification: %s", rep.FirstFailure)
	}
	res.VerifyMs, res.VerifyPerSec = rate(o.events, time.Since(start))
	fmt.Printf("  verify        %8d ms  %12s events/s\n", res.VerifyMs, perSec(res.VerifyPerSec))

	// 4. Tamper with one payload in the middle and expect it to be pinpointed.
	target := o.events / 2
	original := items[target].Record.Content
	tampered := append([]byte(nil), original...)
	if i := slices.Index(tampered, 'd'); i >= 0 {
		tampered[i] = 'D' // e.g. "draft" -> "Draft"
	}
	items[target].Record.Content = tampered
	rep, err = verify.VerifyStream(ctx, &verify.SliceSource{Items: items, BatchSize: 2000}, opts)
	items[target].Record.Content = original
	if err != nil {
		return nil, err
	}
	res.TamperDetected = !rep.Valid && rep.FirstFailure != nil
	if res.TamperDetected {
		res.TamperSequence, res.TamperReason = rep.FirstFailure.Sequence, string(rep.FirstFailure.Code)
		fmt.Printf("  tamper check  modified sequence %d → detected: %s at sequence %d\n",
			target+1, res.TamperReason, res.TamperSequence)
	} else {
		return nil, fmt.Errorf("tampering with sequence %d was NOT detected", target+1)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// HTTP mode

type latency struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

type streamCheck struct {
	Stream         string `json:"stream"`
	Events         int64  `json:"events"`
	LocalValid     bool   `json:"localValid"`
	LocalMs        int64  `json:"localMs"`
	ServerValid    bool   `json:"serverValid"`
	ServerResultMs int64  `json:"serverMs"`
}

type httpResult struct {
	Mode          string        `json:"mode"`
	URL           string        `json:"url"`
	Events        int           `json:"events"`
	Requests      int           `json:"requests"`
	Concurrency   int           `json:"concurrency"`
	BatchSize     int           `json:"batchSize"`
	Streams       int           `json:"streams"`
	IngestMs      int64         `json:"ingestMs"`
	EventsPerSec  float64       `json:"eventsPerSec"`
	LatencyMs     latency       `json:"requestLatencyMs"`
	RateLimited   int64         `json:"rateLimitedRetries"`
	Verifications []streamCheck `json:"verifications"`
}

func runHTTP(ctx context.Context, o options) (*httpResult, error) {
	if o.apiKey == "" {
		return nil, errors.New("HTTP mode needs an API key: -api-key or DELIL_API_KEY")
	}
	if o.concurrency < 1 || o.batch < 1 || o.streams < 1 || o.events < 1 {
		return nil, errors.New("-events, -concurrency, -batch and -streams must be positive")
	}
	if o.prefix == "" {
		o.prefix = "bench-" + time.Now().UTC().Format("20060102-150405")
	}
	c := client.New(o.url, o.apiKey)
	c.UserAgent, c.ClientName = "delil-bench/"+version.Version, "bench"
	c.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		MaxIdleConnsPerHost: o.concurrency * 2, ForceAttemptHTTP2: true}}
	if _, err := c.Health(ctx); err != nil {
		return nil, fmt.Errorf("server not reachable: %w", err)
	}

	streams := make([]string, o.streams)
	for i := range streams {
		streams[i] = fmt.Sprintf("%s-%d", o.prefix, i+1)
	}
	type job struct {
		stream string
		events []client.Event
	}
	jobs := make(chan job)
	go func() {
		defer close(jobs)
		for sent, n := 0, 0; sent < o.events; n++ {
			size := min(o.batch, o.events-sent)
			stream := streams[n%len(streams)]
			batch := make([]client.Event, size)
			for i := range batch {
				in := sampleInput(sent + i)
				before, _ := json.Marshal(in.Before)
				after, _ := json.Marshal(in.After)
				batch[i] = client.Event{Stream: stream, Actor: in.Actor, Action: in.Action, Resource: in.Resource,
					Before: before, After: after, Metadata: in.Metadata, Context: in.Context}
			}
			sent += size
			select {
			case jobs <- job{stream, batch}:
			case <-ctx.Done():
				return
			}
		}
	}()

	fmt.Printf("DƏLİL HTTP benchmark · %s · %s events · %d workers · batch %d · %d streams\n",
		o.url, verify.Thousands(int64(o.events)), o.concurrency, o.batch, o.streams)
	var (
		mu        sync.Mutex
		latencies []time.Duration
		limited   atomic.Int64
		firstErr  error
		wg        sync.WaitGroup
	)
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := time.Now()
	for w := 0; w < o.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				d, err := send(wctx, c, j.events, &limited)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					cancel()
					return
				}
				latencies = append(latencies, d)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if firstErr != nil {
		return nil, firstErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	res := &httpResult{Mode: "http", URL: o.url, Events: o.events, Requests: len(latencies),
		Concurrency: o.concurrency, BatchSize: o.batch, Streams: o.streams, RateLimited: limited.Load()}
	res.IngestMs, res.EventsPerSec = rate(o.events, elapsed)
	slices.Sort(latencies)
	res.LatencyMs = latency{P50: pct(latencies, 50), P95: pct(latencies, 95), P99: pct(latencies, 99), Max: pct(latencies, 100)}
	fmt.Printf("  ingest        %8d ms  %12s events/s  (%d requests, %d rate-limited retries)\n",
		res.IngestMs, perSec(res.EventsPerSec), res.Requests, res.RateLimited)
	fmt.Printf("  latency       p50 %.1f ms · p95 %.1f ms · p99 %.1f ms · max %.1f ms\n",
		res.LatencyMs.P50, res.LatencyMs.P95, res.LatencyMs.P99, res.LatencyMs.Max)

	kf, err := c.TrustedKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys, problems := integrity.NewKeySetLenient(kf.Keys...)
	ok := true
	for _, s := range streams {
		chk := streamCheck{Stream: s}
		t := time.Now()
		rep, err := c.VerifyStreamLocal(ctx, s, verify.StreamOptions{Keys: keys, KeySource: "server",
			RejectedKeys: problems, Verifier: &verify.VerifierInfo{Name: "delil-bench", Version: version.Version, Location: "cli"}})
		if err != nil {
			return nil, fmt.Errorf("verify %s locally: %w", s, err)
		}
		chk.LocalMs, chk.Events, chk.LocalValid = time.Since(t).Milliseconds(), rep.EventsChecked, rep.Valid
		t = time.Now()
		run, err := c.VerifyStreamRemote(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("verify %s on the server: %w", s, err)
		}
		chk.ServerResultMs, chk.ServerValid = time.Since(t).Milliseconds(), run.Status == "passed"
		ok = ok && chk.LocalValid && chk.ServerValid
		fmt.Printf("  verify %-24s %7s events · local %s %5d ms · server %s %5d ms\n", s,
			verify.Thousands(chk.Events), mark(chk.LocalValid), chk.LocalMs, mark(chk.ServerValid), chk.ServerResultMs)
		res.Verifications = append(res.Verifications, chk)
	}
	if !ok {
		return res, errors.New("verification failed for at least one benchmark stream")
	}
	return res, nil
}

// send posts one batch, retrying rate-limited and transient failures with the
// same idempotency key so a retry can never record an event twice.
func send(ctx context.Context, c *client.Client, events []client.Event, limited *atomic.Int64) (time.Duration, error) {
	key := client.NewIdempotencyKey()
	backoff := 50 * time.Millisecond
	for attempt := 0; ; attempt++ {
		t := time.Now()
		var err error
		if len(events) == 1 {
			_, err = c.RecordEvent(ctx, events[0], client.WithIdempotencyKey(key))
		} else {
			_, err = c.RecordBatch(ctx, events, client.WithIdempotencyKey(key))
		}
		if err == nil {
			return time.Since(t), nil
		}
		var apiErr *client.Error
		retryable := errors.Is(err, io.ErrUnexpectedEOF) ||
			(errors.As(err, &apiErr) && (apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500))
		if !retryable || attempt >= 20 || ctx.Err() != nil {
			return 0, err
		}
		if apiErr != nil && apiErr.Status == http.StatusTooManyRequests {
			limited.Add(1)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		backoff = min(backoff*2, 2*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Helpers

func rate(n int, d time.Duration) (int64, float64) {
	return d.Milliseconds(), float64(n) / max(d.Seconds(), 1e-9)
}

func perSec(f float64) string { return verify.Thousands(int64(f)) }

func pct(sorted []time.Duration, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := min(len(sorted)-1, (len(sorted)*p+99)/100-1)
	return float64(sorted[max(i, 0)].Microseconds()) / 1000
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}
