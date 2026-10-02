package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/serxan22/delil/internal/auth"
	"github.com/serxan22/delil/internal/store"
	"github.com/serxan22/delil/pkg/integrity"
)

func ts(t time.Time) string { return integrity.FormatTime(t) }

func tsPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := integrity.FormatTime(*t)
	return &s
}

type listView[T any] struct {
	Object     string `json:"object"`
	Data       []T    `json:"data"`
	HasMore    bool   `json:"hasMore"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func list[T any](data []T) listView[T] {
	if data == nil {
		data = []T{}
	}
	return listView[T]{Object: "list", Data: data}
}

// ---------------------------------------------------------------------------
// Events

type receiptView struct {
	Object             string `json:"object"`
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
}

// receipt renders a committed event. verificationStatus "valid" means the
// server re-verified the signature with the public key and the link to the
// predecessor before committing; it is not a substitute for verifying the
// stream.
func receipt(rec integrity.Record) receiptView {
	return receiptView{Object: "event_receipt", ID: rec.EventID, Stream: rec.Stream, Sequence: rec.Sequence,
		RecordedAt: rec.RecordedAt, EventHash: rec.EventHash.String(), PreviousHash: rec.PreviousHash.String(),
		PayloadHash: rec.PayloadHash.String(), Signature: rec.Signature.String(), SigningKeyID: rec.KeyID,
		VerificationStatus: "valid"}
}

type integrityView struct {
	SchemaVersion int    `json:"schemaVersion"`
	PreviousHash  string `json:"previousHash"`
	PayloadHash   string `json:"payloadHash"`
	EventHash     string `json:"eventHash"`
	Signature     string `json:"signature"`
	SigningKeyID  string `json:"signingKeyId"`
	Algorithm     string `json:"algorithm"`
}

type eventVerificationView struct {
	Status     string  `json:"status"` // verified, failed, unverified
	VerifiedAt *string `json:"verifiedAt,omitempty"`
	RunID      string  `json:"runId,omitempty"`
}

type eventView struct {
	Object       string                    `json:"object"`
	ID           string                    `json:"id"`
	Stream       string                    `json:"stream"`
	Sequence     int64                     `json:"sequence"`
	Action       string                    `json:"action"`
	Actor        integrity.Actor           `json:"actor"`
	Resource     *integrity.Resource       `json:"resource,omitempty"`
	Before       json.RawMessage           `json:"before,omitempty"`
	After        json.RawMessage           `json:"after,omitempty"`
	Changes      json.RawMessage           `json:"changes,omitempty"`
	Data         json.RawMessage           `json:"data,omitempty"`
	Metadata     json.RawMessage           `json:"metadata,omitempty"`
	Context      *integrity.RequestContext `json:"context,omitempty"`
	OccurredAt   string                    `json:"occurredAt,omitempty"`
	RecordedAt   string                    `json:"recordedAt"`
	Redactions   []string                  `json:"redactions,omitempty"`
	Integrity    integrityView             `json:"integrity"`
	Verification *eventVerificationView    `json:"verification,omitempty"`
}

// rawContent mirrors integrity.Content but keeps every free-form member raw.
type rawContent struct {
	Action     string                    `json:"action"`
	Actor      integrity.Actor           `json:"actor"`
	Resource   *integrity.Resource       `json:"resource"`
	Before     json.RawMessage           `json:"before"`
	After      json.RawMessage           `json:"after"`
	Changes    json.RawMessage           `json:"changes"`
	Data       json.RawMessage           `json:"data"`
	Metadata   json.RawMessage           `json:"metadata"`
	Context    *integrity.RequestContext `json:"context"`
	OccurredAt string                    `json:"occurredAt"`
	Redactions []string                  `json:"redactions"`
}

// renderEvent builds the API representation from the signed content, never
// from the index columns.
func renderEvent(e store.Event) eventView {
	rec := e.Record()
	v := eventView{Object: "event", ID: e.ID, Stream: e.StreamName, Sequence: e.Sequence,
		RecordedAt: rec.RecordedAt,
		Integrity: integrityView{SchemaVersion: e.SchemaVersion, PreviousHash: rec.PreviousHash.String(),
			PayloadHash: rec.PayloadHash.String(), EventHash: rec.EventHash.String(), Signature: rec.Signature.String(),
			SigningKeyID: e.SigningKeyID, Algorithm: integrity.AlgorithmEd25519}}
	var c rawContent
	if err := json.Unmarshal([]byte(e.Content), &c); err == nil {
		v.Action, v.Actor, v.Resource = c.Action, c.Actor, c.Resource
		v.Before, v.After, v.Changes, v.Data, v.Metadata = c.Before, c.After, c.Changes, c.Data, c.Metadata
		v.Context, v.OccurredAt, v.Redactions = c.Context, c.OccurredAt, c.Redactions
	}
	return v
}

func eventStatus(e store.Event, sv *store.StreamVerification) *eventVerificationView {
	if sv == nil || sv.LastSequence == nil || e.Sequence > *sv.LastSequence {
		return &eventVerificationView{Status: "unverified"}
	}
	view := &eventVerificationView{Status: "verified", VerifiedAt: tsPtr(&sv.CompletedAt), RunID: sv.RunID}
	if sv.FirstFailureSequence != nil && e.Sequence >= *sv.FirstFailureSequence {
		view.Status = "failed"
	}
	return view
}

// ---------------------------------------------------------------------------
// Streams, checkpoints, verification

type streamVerificationView struct {
	Status               string  `json:"status"` // passed, failed, never
	VerifiedAt           *string `json:"verifiedAt,omitempty"`
	RunID                string  `json:"runId,omitempty"`
	LastSequence         *int64  `json:"lastSequence,omitempty"`
	FailureCount         int     `json:"failureCount"`
	FirstFailureSequence *int64  `json:"firstFailureSequence,omitempty"`
}

type streamView struct {
	Object                 string                 `json:"object"`
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	HeadSequence           int64                  `json:"headSequence"`
	HeadHash               string                 `json:"headHash"`
	LastEventAt            *string                `json:"lastEventAt,omitempty"`
	LastCheckpointSequence int64                  `json:"lastCheckpointSequence"`
	CreatedAt              string                 `json:"createdAt"`
	Verification           streamVerificationView `json:"verification"`
}

func renderStream(st store.Stream, sv *store.StreamVerification) streamView {
	v := streamView{Object: "stream", ID: st.ID, Name: st.Name, HeadSequence: st.HeadSequence,
		HeadHash: st.HeadHashValue().String(), LastEventAt: tsPtr(st.HeadRecordedAt),
		LastCheckpointSequence: st.LastCheckpointSequence, CreatedAt: ts(st.CreatedAt),
		Verification: streamVerificationView{Status: "never"}}
	if sv != nil {
		v.Verification = streamVerificationView{Status: "passed", VerifiedAt: tsPtr(&sv.CompletedAt), RunID: sv.RunID,
			LastSequence: sv.LastSequence, FailureCount: sv.FailureCount, FirstFailureSequence: sv.FirstFailureSequence}
		if !sv.Valid {
			v.Verification.Status = "failed"
		}
	}
	return v
}

type checkpointView struct {
	Object string `json:"object"`
	integrity.Checkpoint
}

type runView struct {
	Object         string          `json:"object"`
	ID             string          `json:"id"`
	Scope          string          `json:"scope"`
	Target         string          `json:"target,omitempty"`
	Status         string          `json:"status"`
	Trigger        string          `json:"trigger"`
	TriggeredBy    string          `json:"triggeredBy,omitempty"`
	StreamsChecked int             `json:"streamsChecked"`
	EventsChecked  int64           `json:"eventsChecked"`
	FailureCount   int             `json:"failureCount"`
	StartedAt      string          `json:"startedAt"`
	CompletedAt    *string         `json:"completedAt,omitempty"`
	Report         json.RawMessage `json:"report,omitempty"`
}

func renderRun(r store.VerificationRun) runView {
	return runView{Object: "verification_run", ID: r.ID, Scope: r.Scope, Target: r.Target, Status: r.Status,
		Trigger: r.Trigger, TriggeredBy: r.TriggeredBy, StreamsChecked: r.StreamsChecked, EventsChecked: r.EventsChecked,
		FailureCount: r.FailureCount, StartedAt: ts(r.StartedAt), CompletedAt: tsPtr(r.CompletedAt), Report: r.Report}
}

// ---------------------------------------------------------------------------
// Exports, keys, projects, users

type exportView struct {
	Object            string          `json:"object"`
	ID                string          `json:"id"`
	Stream            string          `json:"stream"`
	Status            string          `json:"status"`
	Params            json.RawMessage `json:"params"`
	CreatedBy         string          `json:"createdBy,omitempty"`
	CreatedAt         string          `json:"createdAt"`
	CompletedAt       *string         `json:"completedAt,omitempty"`
	ExpiresAt         *string         `json:"expiresAt,omitempty"`
	ChainEvents       *int64          `json:"chainEvents,omitempty"`
	DisclosedEvents   *int64          `json:"disclosedEvents,omitempty"`
	FirstSequence     *int64          `json:"firstSequence,omitempty"`
	LastSequence      *int64          `json:"lastSequence,omitempty"`
	SizeBytes         *int64          `json:"sizeBytes,omitempty"`
	SHA256            string          `json:"sha256,omitempty"`
	ManifestHash      string          `json:"manifestHash,omitempty"`
	VerificationValid *bool           `json:"verificationValid,omitempty"`
	Error             string          `json:"error,omitempty"`
	DownloadURL       string          `json:"downloadUrl,omitempty"`
}

func renderExport(x store.Export) exportView {
	v := exportView{Object: "export", ID: x.ID, Stream: x.StreamName, Status: x.Status, Params: x.Params,
		CreatedBy: x.CreatedBy, CreatedAt: ts(x.CreatedAt), CompletedAt: tsPtr(x.CompletedAt), ExpiresAt: tsPtr(x.ExpiresAt),
		ChainEvents: x.ChainEvents, DisclosedEvents: x.DisclosedEvents, FirstSequence: x.FirstSequence,
		LastSequence: x.LastSequence, SizeBytes: x.SizeBytes, VerificationValid: x.VerificationValid, Error: x.Error}
	if len(x.SHA256) > 0 {
		v.SHA256 = hex.EncodeToString(x.SHA256)
	}
	if len(x.ManifestHash) > 0 {
		v.ManifestHash = hex.EncodeToString(x.ManifestHash)
	}
	if x.Status == "completed" {
		v.DownloadURL = "/v1/exports/" + x.ID + "/download"
	}
	return v
}

type apiKeyView struct {
	Object     string   `json:"object"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes"`
	CreatedBy  string   `json:"createdBy,omitempty"`
	CreatedAt  string   `json:"createdAt"`
	LastUsedAt *string  `json:"lastUsedAt,omitempty"`
	ExpiresAt  *string  `json:"expiresAt,omitempty"`
	RevokedAt  *string  `json:"revokedAt,omitempty"`
	// Secret is only present in the response that creates the key.
	Secret string `json:"secret,omitempty"`
}

func renderAPIKey(k store.APIKey) apiKeyView {
	return apiKeyView{Object: "api_key", ID: k.ID, Name: k.Name, Prefix: auth.DisplayPrefix(k.LookupID), Scopes: k.Scopes,
		CreatedBy: k.CreatedBy, CreatedAt: ts(k.CreatedAt), LastUsedAt: tsPtr(k.LastUsedAt), ExpiresAt: tsPtr(k.ExpiresAt),
		RevokedAt: tsPtr(k.RevokedAt)}
}

type signingKeyView struct {
	Object           string  `json:"object"`
	ID               string  `json:"id"`
	Algorithm        string  `json:"algorithm"`
	PublicKey        string  `json:"publicKey"`
	Fingerprint      string  `json:"fingerprint"`
	Status           string  `json:"status"`
	Provider         string  `json:"provider"`
	CreatedAt        string  `json:"createdAt"`
	ActivatedAt      string  `json:"activatedAt"`
	RetiredAt        *string `json:"retiredAt,omitempty"`
	RevokedAt        *string `json:"revokedAt,omitempty"`
	RevocationReason string  `json:"revocationReason,omitempty"`
	EventsSigned     int64   `json:"eventsSigned"`
}

func renderSigningKey(k store.SigningKey) signingKeyView {
	return signingKeyView{Object: "signing_key", ID: k.ID, Algorithm: k.Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey), Fingerprint: k.Fingerprint, Status: k.Status,
		Provider: k.Provider, CreatedAt: ts(k.CreatedAt), ActivatedAt: ts(k.ActivatedAt), RetiredAt: tsPtr(k.RetiredAt),
		RevokedAt: tsPtr(k.RevokedAt), RevocationReason: k.RevocationReason, EventsSigned: k.EventCount}
}

type tenantView struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type projectView struct {
	Object    string          `json:"object"`
	ID        string          `json:"id"`
	Slug      string          `json:"slug"`
	Name      string          `json:"name"`
	Settings  json.RawMessage `json:"settings,omitempty"`
	CreatedAt string          `json:"createdAt"`
	Tenant    *tenantView     `json:"tenant,omitempty"`
}

func renderProject(p store.Project, settings any) projectView {
	v := projectView{Object: "project", ID: p.ID, Slug: p.Slug, Name: p.Name, CreatedAt: ts(p.CreatedAt)}
	if settings != nil {
		v.Settings, _ = json.Marshal(settings)
	}
	return v
}

type userView struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	DisplayName string  `json:"displayName"`
	Role        string  `json:"role"`
	CreatedAt   string  `json:"createdAt"`
	LastLoginAt *string `json:"lastLoginAt,omitempty"`
	Disabled    bool    `json:"disabled"`
}

func renderUser(u store.User) userView {
	return userView{Object: "user", ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: u.Role,
		CreatedAt: ts(u.CreatedAt), LastLoginAt: tsPtr(u.LastLoginAt), Disabled: u.DisabledAt != nil}
}
