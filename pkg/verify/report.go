// Package verify is DƏLİL's verification engine. It independently recomputes
// canonical payloads, payload hashes, event hashes, chain links, sequence
// continuity and signatures, and checks stream heads and signed checkpoints.
//
// The same code runs inside the API server, inside the delil CLI (fed with
// records downloaded over HTTP, so the server does not have to be trusted) and
// inside the offline evidence-package verifier. It performs no I/O.
package verify

import "fmt"

// Code identifies a specific verification failure.
type Code string

// Failure codes. They are part of the public API and are stable.
const (
	CodeUnsupportedSchema    Code = "unsupported_schema_version"
	CodeMalformedRecord      Code = "malformed_record"
	CodeContextMismatch      Code = "context_mismatch"
	CodePayloadMissing       Code = "payload_missing"
	CodePayloadInvalid       Code = "payload_invalid"
	CodePayloadNotCanonical  Code = "payload_not_canonical"
	CodePayloadHashMismatch  Code = "payload_hash_mismatch"
	CodeIndexedFieldMismatch Code = "indexed_field_mismatch"
	CodeEventHashMismatch    Code = "event_hash_mismatch"
	CodeUnknownSigningKey    Code = "unknown_signing_key"
	CodeSignatureInvalid     Code = "signature_invalid"
	CodeSigningKeyRevoked    Code = "signing_key_revoked"
	CodeKeyOutsideValidity   Code = "signing_key_outside_validity"
	CodeSequenceGap          Code = "sequence_gap"
	CodeSequenceOutOfOrder   Code = "sequence_out_of_order"
	CodePreviousHashMismatch Code = "previous_hash_mismatch"
	CodeAnchorMismatch       Code = "anchor_mismatch"
	CodeTimestampRegression  Code = "timestamp_regression"
	CodeHeadMismatch         Code = "head_mismatch"
	CodeCheckpointInvalid    Code = "checkpoint_invalid"
	CodeCheckpointMismatch   Code = "checkpoint_mismatch"
	CodeCheckpointBeyondHead Code = "checkpoint_beyond_head"
)

// Check is one of the categories summarized in a report.
type Check string

// Check categories.
const (
	CheckHashChain     Check = "hashChain"
	CheckPayloadHashes Check = "payloadHashes"
	CheckSignatures    Check = "signatures"
	CheckOrdering      Check = "ordering"
	CheckCheckpoints   Check = "checkpoints"
	CheckStreamHead    Check = "streamHead"
)

var codeCheck = map[Code]Check{
	CodeUnsupportedSchema:    CheckHashChain,
	CodeMalformedRecord:      CheckHashChain,
	CodeContextMismatch:      CheckHashChain,
	CodePayloadMissing:       CheckPayloadHashes,
	CodePayloadInvalid:       CheckPayloadHashes,
	CodePayloadNotCanonical:  CheckPayloadHashes,
	CodePayloadHashMismatch:  CheckPayloadHashes,
	CodeIndexedFieldMismatch: CheckPayloadHashes,
	CodeEventHashMismatch:    CheckHashChain,
	CodeUnknownSigningKey:    CheckSignatures,
	CodeSignatureInvalid:     CheckSignatures,
	CodeSigningKeyRevoked:    CheckSignatures,
	CodeKeyOutsideValidity:   CheckSignatures,
	CodeSequenceGap:          CheckOrdering,
	CodeSequenceOutOfOrder:   CheckOrdering,
	CodePreviousHashMismatch: CheckHashChain,
	CodeAnchorMismatch:       CheckHashChain,
	CodeTimestampRegression:  CheckOrdering,
	CodeHeadMismatch:         CheckStreamHead,
	CodeCheckpointInvalid:    CheckCheckpoints,
	CodeCheckpointMismatch:   CheckCheckpoints,
	CodeCheckpointBeyondHead: CheckCheckpoints,
}

// CheckOf returns the category a code belongs to.
func CheckOf(c Code) Check { return codeCheck[c] }

// Severity distinguishes integrity failures from advisory findings.
type Severity string

// Severities.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Failure is a single finding.
type Failure struct {
	Code     Code     `json:"code"`
	Check    Check    `json:"check"`
	Severity Severity `json:"severity"`
	Sequence int64    `json:"sequence,omitempty"`
	EventID  string   `json:"eventId,omitempty"`
	Message  string   `json:"message"`
	Expected string   `json:"expected,omitempty"`
	Found    string   `json:"found,omitempty"`
}

func (f Failure) String() string {
	if f.Sequence > 0 {
		return fmt.Sprintf("sequence %d: %s: %s", f.Sequence, f.Code, f.Message)
	}
	return fmt.Sprintf("%s: %s", f.Code, f.Message)
}

// Status is the outcome of one check category.
type Status string

// Statuses.
const (
	StatusValid   Status = "valid"
	StatusInvalid Status = "invalid"
	StatusSkipped Status = "skipped"
)

// Checks summarizes every category. Field order is the display order.
type Checks struct {
	HashChain     Status `json:"hashChain"`
	PayloadHashes Status `json:"payloadHashes"`
	Signatures    Status `json:"signatures"`
	Ordering      Status `json:"ordering"`
	Checkpoints   Status `json:"checkpoints"`
	StreamHead    Status `json:"streamHead"`
}

// Get returns the status of a category.
func (c Checks) Get(check Check) Status {
	switch check {
	case CheckHashChain:
		return c.HashChain
	case CheckPayloadHashes:
		return c.PayloadHashes
	case CheckSignatures:
		return c.Signatures
	case CheckOrdering:
		return c.Ordering
	case CheckCheckpoints:
		return c.Checkpoints
	case CheckStreamHead:
		return c.StreamHead
	}
	return StatusSkipped
}

// Result values.
const (
	ResultValid   = "valid"
	ResultInvalid = "invalid"
)

// Scope values.
const (
	ScopeStream          = "stream"
	ScopeEvent           = "event"
	ScopeEvidencePackage = "evidence_package"
)

// VerifierInfo identifies the software that produced a report and where it
// ran ("server", "cli", "offline").
type VerifierInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Location string `json:"location"`
}

// Report is the machine-readable verification result.
type Report struct {
	Object              string        `json:"object"`
	Scope               string        `json:"scope"`
	Result              string        `json:"result"`
	Valid               bool          `json:"valid"`
	TamperingDetected   bool          `json:"tamperingDetected"`
	TenantID            string        `json:"tenantId,omitempty"`
	ProjectID           string        `json:"projectId,omitempty"`
	Stream              string        `json:"stream,omitempty"`
	EventID             string        `json:"eventId,omitempty"`
	EventsChecked       int64         `json:"eventsChecked"`
	PayloadsChecked     int64         `json:"payloadsChecked"`
	FirstSequence       int64         `json:"firstSequence,omitempty"`
	LastSequence        int64         `json:"lastSequence,omitempty"`
	LastEventHash       string        `json:"lastEventHash,omitempty"`
	Anchor              string        `json:"anchor"`
	Checks              Checks        `json:"checks"`
	CheckpointsVerified int           `json:"checkpointsVerified"`
	KeysUsed            []string      `json:"keysUsed"`
	KeySource           string        `json:"keySource,omitempty"`
	FirstFailure        *Failure      `json:"firstFailure"`
	Failures            []Failure     `json:"failures"`
	FailureCount        int           `json:"failureCount"`
	FailuresTruncated   bool          `json:"failuresTruncated"`
	Warnings            []Failure     `json:"warnings"`
	StartedAt           string        `json:"startedAt"`
	CompletedAt         string        `json:"completedAt"`
	DurationMs          int64         `json:"durationMs"`
	Verifier            *VerifierInfo `json:"verifier,omitempty"`
}
