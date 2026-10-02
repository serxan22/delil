// Package client is a Go client for the DƏLİL REST API. The delil CLI is
// built on it, and it is the foundation of the Go SDK.
//
//	c := client.New("http://localhost:8080", os.Getenv("DELIL_API_KEY"))
//	receipt, err := c.RecordEvent(ctx, client.Event{...}, client.WithIdempotencyKey("refund-42"))
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/serxan22/delil/pkg/evidence"
	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/verify"
)

// Client talks to one DƏLİL server with one API key.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTP       *http.Client
	UserAgent  string
	ClientName string // sent as Delil-Client, e.g. "cli"
}

// New returns a client with a 30-second timeout.
func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey,
		HTTP: &http.Client{Timeout: 30 * time.Second}, UserAgent: "delil-go-client"}
}

// Error is an error returned by the API.
type Error struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Details   json.RawMessage
}

func (e *Error) Error() string {
	s := fmt.Sprintf("%s (HTTP %d): %s", e.Code, e.Status, e.Message)
	if e.RequestID != "" {
		s += " [request " + e.RequestID + "]"
	}
	return s
}

// IsNotFound reports whether err is a 404 from the API.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

type requestOptions struct {
	headers map[string]string
}

// Option customises a request.
type Option func(*requestOptions)

// WithIdempotencyKey makes a write safely retryable.
func WithIdempotencyKey(key string) Option {
	return func(o *requestOptions) { o.headers["Idempotency-Key"] = key }
}

// NewIdempotencyKey returns a random key.
func NewIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body any, opts []Option) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.ClientName != "" {
		req.Header.Set("Delil-Client", c.ClientName)
	}
	o := &requestOptions{headers: map[string]string{}}
	for _, opt := range opts {
		opt(o)
	}
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, opts ...Option) (http.Header, error) {
	req, err := c.newRequest(ctx, method, path, body, opts)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode >= 400 {
		return resp.Header, decodeError(resp, data)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.Header, fmt.Errorf("decode %s %s response: %w", method, path, err)
		}
	}
	return resp.Header, nil
}

func decodeError(resp *http.Response, data []byte) error {
	var env struct {
		Error struct {
			Code      string          `json:"code"`
			Message   string          `json:"message"`
			RequestID string          `json:"requestId"`
			Details   json.RawMessage `json:"details"`
		} `json:"error"`
	}
	e := &Error{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Request-Id")}
	if json.Unmarshal(data, &env) == nil && env.Error.Code != "" {
		e.Code, e.Message, e.Details = env.Error.Code, env.Error.Message, env.Error.Details
		if env.Error.RequestID != "" {
			e.RequestID = env.Error.RequestID
		}
	} else {
		e.Code, e.Message = "http_error", strings.TrimSpace(string(data))
	}
	return e
}

// ---------------------------------------------------------------------------
// Types

// Actor, Resource and RequestContext describe an event.
type (
	Actor          = integrity.Actor
	Resource       = integrity.Resource
	RequestContext = integrity.RequestContext
)

// Event is an event submission.
type Event struct {
	Stream     string          `json:"stream"`
	Actor      Actor           `json:"actor"`
	Action     string          `json:"action"`
	Resource   *Resource       `json:"resource,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Metadata   map[string]any  `json:"metadata,omitempty"`
	Context    *RequestContext `json:"context,omitempty"`
	OccurredAt *time.Time      `json:"occurredAt,omitempty"`
}

// Receipt is returned when an event is committed.
type Receipt struct {
	ID                 string `json:"id"`
	Stream             string `json:"stream"`
	Sequence           int64  `json:"sequence"`
	RecordedAt         string `json:"recordedAt"`
	EventHash          string `json:"eventHash"`
	PreviousHash       string `json:"previousHash"`
	PayloadHash        string `json:"payloadHash"`
	Signature          string `json:"signature"`
	SigningKeyID       string `json:"signingKeyId"`
	VerificationStatus string `json:"verificationStatus"`
	Replayed           bool   `json:"-"`
}

// StoredEvent is an event as returned by the API.
type StoredEvent struct {
	ID         string          `json:"id"`
	Stream     string          `json:"stream"`
	Sequence   int64           `json:"sequence"`
	Action     string          `json:"action"`
	Actor      Actor           `json:"actor"`
	Resource   *Resource       `json:"resource"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	Changes    json.RawMessage `json:"changes"`
	Data       json.RawMessage `json:"data"`
	Metadata   json.RawMessage `json:"metadata"`
	Context    *RequestContext `json:"context"`
	OccurredAt string          `json:"occurredAt"`
	RecordedAt string          `json:"recordedAt"`
	Redactions []string        `json:"redactions"`
	Integrity  struct {
		SchemaVersion int    `json:"schemaVersion"`
		PreviousHash  string `json:"previousHash"`
		PayloadHash   string `json:"payloadHash"`
		EventHash     string `json:"eventHash"`
		Signature     string `json:"signature"`
		SigningKeyID  string `json:"signingKeyId"`
		Algorithm     string `json:"algorithm"`
	} `json:"integrity"`
	Verification *struct {
		Status     string `json:"status"`
		VerifiedAt string `json:"verifiedAt"`
	} `json:"verification"`
}

// EventPage is one page of events.
type EventPage struct {
	Data       []StoredEvent `json:"data"`
	HasMore    bool          `json:"hasMore"`
	NextCursor string        `json:"nextCursor"`
}

// EventQuery filters event listings.
type EventQuery struct {
	Stream, ActorID, ActorType, Action, ResourceType, ResourceID, From, To, VerificationStatus, Cursor string
	Limit                                                                                              int
}

// Stream describes an audit stream.
type Stream struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	HeadSequence           int64  `json:"headSequence"`
	HeadHash               string `json:"headHash"`
	LastEventAt            string `json:"lastEventAt"`
	LastCheckpointSequence int64  `json:"lastCheckpointSequence"`
	Verification           struct {
		Status       string `json:"status"`
		VerifiedAt   string `json:"verifiedAt"`
		FailureCount int    `json:"failureCount"`
	} `json:"verification"`
}

// ChainPage is a page of raw chain records.
type ChainPage struct {
	Stream            string             `json:"stream"`
	TenantID          string             `json:"tenantId"`
	ProjectID         string             `json:"projectId"`
	Records           []integrity.Record `json:"records"`
	HasMore           bool               `json:"hasMore"`
	NextAfterSequence int64              `json:"nextAfterSequence"`
	Head              struct {
		Sequence int64  `json:"sequence"`
		Hash     string `json:"hash"`
	} `json:"head"`
}

// VerificationRun is a server-side verification.
type VerificationRun struct {
	ID             string          `json:"id"`
	Scope          string          `json:"scope"`
	Target         string          `json:"target"`
	Status         string          `json:"status"`
	Trigger        string          `json:"trigger"`
	StreamsChecked int             `json:"streamsChecked"`
	EventsChecked  int64           `json:"eventsChecked"`
	FailureCount   int             `json:"failureCount"`
	StartedAt      string          `json:"startedAt"`
	CompletedAt    string          `json:"completedAt"`
	Report         json.RawMessage `json:"report"`
}

// ExportRequest selects what to export.
type ExportRequest struct {
	Stream       string `json:"stream"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	FromSequence *int64 `json:"fromSequence,omitempty"`
	ToSequence   *int64 `json:"toSequence,omitempty"`
	ActorID      string `json:"actorId,omitempty"`
	Action       string `json:"action,omitempty"`
	ResourceType string `json:"resourceType,omitempty"`
	ResourceID   string `json:"resourceId,omitempty"`
}

// Export is an evidence export job.
type Export struct {
	ID                string `json:"id"`
	Stream            string `json:"stream"`
	Status            string `json:"status"`
	CreatedAt         string `json:"createdAt"`
	CompletedAt       string `json:"completedAt"`
	ExpiresAt         string `json:"expiresAt"`
	ChainEvents       int64  `json:"chainEvents"`
	DisclosedEvents   int64  `json:"disclosedEvents"`
	FirstSequence     int64  `json:"firstSequence"`
	LastSequence      int64  `json:"lastSequence"`
	SizeBytes         int64  `json:"sizeBytes"`
	SHA256            string `json:"sha256"`
	ManifestHash      string `json:"manifestHash"`
	VerificationValid *bool  `json:"verificationValid"`
	Error             string `json:"error"`
}

// SigningKey describes a signing key.
type SigningKey struct {
	ID           string `json:"id"`
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"publicKey"`
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"`
	Provider     string `json:"provider"`
	ActivatedAt  string `json:"activatedAt"`
	RetiredAt    string `json:"retiredAt"`
	RevokedAt    string `json:"revokedAt"`
	EventsSigned int64  `json:"eventsSigned"`
}

// Project describes the current project.
type Project struct {
	ID       string          `json:"id"`
	Slug     string          `json:"slug"`
	Name     string          `json:"name"`
	Settings json.RawMessage `json:"settings"`
	Tenant   *struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"tenant"`
}

// Overview summarizes a project.
type Overview struct {
	Stats struct {
		EventsTotal   int64  `json:"eventsTotal"`
		EventsToday   int64  `json:"eventsToday"`
		Streams       int    `json:"streams"`
		ActiveStreams int    `json:"activeStreams"`
		LastEventAt   string `json:"lastEventAt"`
	} `json:"stats"`
	Verification struct {
		Status            string           `json:"status"`
		StreamsPassing    int              `json:"streamsPassing"`
		StreamsFailing    int              `json:"streamsFailing"`
		StreamsUnverified int              `json:"streamsUnverified"`
		LatestRun         *VerificationRun `json:"latestRun"`
	} `json:"verification"`
	SigningKey *SigningKey `json:"signingKey"`
}

type list[T any] struct {
	Data []T `json:"data"`
}

// ---------------------------------------------------------------------------
// Endpoints

// Health checks /health.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	_, err := c.do(ctx, http.MethodGet, "/health", nil, &out)
	return out, err
}

// RecordEvent records one event. Without an explicit idempotency key a random
// one is generated, which makes retries of this call safe.
func (c *Client) RecordEvent(ctx context.Context, e Event, opts ...Option) (*Receipt, error) {
	opts = append([]Option{WithIdempotencyKey(NewIdempotencyKey())}, opts...)
	var r Receipt
	hdr, err := c.do(ctx, http.MethodPost, "/v1/events", e, &r, opts...)
	if err != nil {
		return nil, err
	}
	r.Replayed = hdr.Get("Idempotent-Replayed") == "true"
	return &r, nil
}

// RecordBatch records events atomically.
func (c *Client) RecordBatch(ctx context.Context, events []Event, opts ...Option) ([]Receipt, error) {
	opts = append([]Option{WithIdempotencyKey(NewIdempotencyKey())}, opts...)
	var out list[Receipt]
	_, err := c.do(ctx, http.MethodPost, "/v1/events/batch", map[string]any{"events": events}, &out, opts...)
	return out.Data, err
}

// GetEvent returns one event.
func (c *Client) GetEvent(ctx context.Context, id string) (*StoredEvent, error) {
	var e StoredEvent
	_, err := c.do(ctx, http.MethodGet, "/v1/events/"+url.PathEscape(id), nil, &e)
	return &e, err
}

// ListEvents returns a page of events, newest first.
func (c *Client) ListEvents(ctx context.Context, q EventQuery) (*EventPage, error) {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("stream", q.Stream)
	set("actorId", q.ActorID)
	set("actorType", q.ActorType)
	set("action", q.Action)
	set("resourceType", q.ResourceType)
	set("resourceId", q.ResourceID)
	set("from", q.From)
	set("to", q.To)
	set("verificationStatus", q.VerificationStatus)
	set("cursor", q.Cursor)
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	var page EventPage
	_, err := c.do(ctx, http.MethodGet, "/v1/events?"+v.Encode(), nil, &page)
	return &page, err
}

// Streams lists streams.
func (c *Client) Streams(ctx context.Context) ([]Stream, error) {
	var out list[Stream]
	_, err := c.do(ctx, http.MethodGet, "/v1/streams", nil, &out)
	return out.Data, err
}

// Stream returns one stream.
func (c *Client) Stream(ctx context.Context, name string) (*Stream, error) {
	var s Stream
	_, err := c.do(ctx, http.MethodGet, "/v1/streams/"+url.PathEscape(name), nil, &s)
	return &s, err
}

// Chain returns raw chain records with sequence > after.
func (c *Client) Chain(ctx context.Context, stream string, after int64, limit int) (*ChainPage, error) {
	var p ChainPage
	path := fmt.Sprintf("/v1/streams/%s/chain?afterSequence=%d&limit=%d", url.PathEscape(stream), after, limit)
	_, err := c.do(ctx, http.MethodGet, path, nil, &p)
	return &p, err
}

// Checkpoints lists a stream's signed checkpoints.
func (c *Client) Checkpoints(ctx context.Context, stream string) ([]integrity.Checkpoint, error) {
	var out list[integrity.Checkpoint]
	_, err := c.do(ctx, http.MethodGet, "/v1/streams/"+url.PathEscape(stream)+"/checkpoints", nil, &out)
	return out.Data, err
}

// CreateCheckpoint signs the stream's current head.
func (c *Client) CreateCheckpoint(ctx context.Context, stream string) (*integrity.Checkpoint, error) {
	var cp integrity.Checkpoint
	_, err := c.do(ctx, http.MethodPost, "/v1/streams/"+url.PathEscape(stream)+"/checkpoints", nil, &cp)
	return &cp, err
}

// VerifyStreamRemote asks the server to verify a stream.
func (c *Client) VerifyStreamRemote(ctx context.Context, stream string) (*VerificationRun, error) {
	var run VerificationRun
	_, err := c.do(ctx, http.MethodPost, "/v1/streams/"+url.PathEscape(stream)+"/verify", nil, &run)
	return &run, err
}

// VerifyProjectRemote asks the server to verify every stream.
func (c *Client) VerifyProjectRemote(ctx context.Context) (*VerificationRun, error) {
	var run VerificationRun
	_, err := c.do(ctx, http.MethodPost, "/v1/verify", nil, &run)
	return &run, err
}

// VerifyEventRemote asks the server to verify one event.
func (c *Client) VerifyEventRemote(ctx context.Context, id string) (*verify.Report, error) {
	var rep verify.Report
	_, err := c.do(ctx, http.MethodGet, "/v1/events/"+url.PathEscape(id)+"/verify", nil, &rep)
	return &rep, err
}

// CreateExport queues an evidence export.
func (c *Client) CreateExport(ctx context.Context, req ExportRequest) (*Export, error) {
	var x Export
	_, err := c.do(ctx, http.MethodPost, "/v1/exports", req, &x)
	return &x, err
}

// GetExport returns an export.
func (c *Client) GetExport(ctx context.Context, id string) (*Export, error) {
	var x Export
	_, err := c.do(ctx, http.MethodGet, "/v1/exports/"+url.PathEscape(id), nil, &x)
	return &x, err
}

// WaitForExport polls until the export completes or fails.
func (c *Client) WaitForExport(ctx context.Context, id string, interval time.Duration) (*Export, error) {
	for {
		x, err := c.GetExport(ctx, id)
		if err != nil {
			return nil, err
		}
		switch x.Status {
		case "completed":
			return x, nil
		case "failed", "expired":
			return x, fmt.Errorf("export %s %s: %s", id, x.Status, x.Error)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// DownloadExport streams the package into w.
func (c *Client) DownloadExport(ctx context.Context, id string, w io.Writer) (int64, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/exports/"+url.PathEscape(id)+"/download", nil, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return 0, decodeError(resp, data)
	}
	return io.Copy(w, resp.Body)
}

// SigningKeys lists the project's signing keys.
func (c *Client) SigningKeys(ctx context.Context) ([]SigningKey, error) {
	var out list[SigningKey]
	_, err := c.do(ctx, http.MethodGet, "/v1/signing-keys", nil, &out)
	return out.Data, err
}

// TrustedKeys returns the public keys in trusted-keys file format.
func (c *Client) TrustedKeys(ctx context.Context) (*evidence.KeysFile, error) {
	var kf evidence.KeysFile
	_, err := c.do(ctx, http.MethodGet, "/v1/signing-keys/export", nil, &kf)
	return &kf, err
}

// RotateSigningKey rotates the project's signing key.
func (c *Client) RotateSigningKey(ctx context.Context) (previous, current *SigningKey, err error) {
	var out struct {
		Previous SigningKey `json:"previous"`
		Current  SigningKey `json:"current"`
	}
	_, err = c.do(ctx, http.MethodPost, "/v1/signing-keys/rotate", nil, &out)
	return &out.Previous, &out.Current, err
}

// Project returns the current project.
func (c *Client) Project(ctx context.Context) (*Project, error) {
	var p Project
	_, err := c.do(ctx, http.MethodGet, "/v1/project", nil, &p)
	return &p, err
}

// Overview returns project statistics.
func (c *Client) Overview(ctx context.Context) (*Overview, error) {
	var o Overview
	_, err := c.do(ctx, http.MethodGet, "/v1/overview", nil, &o)
	return &o, err
}
