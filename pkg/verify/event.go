package verify

import (
	"fmt"

	"github.com/serxan22/delil/pkg/integrity"
)

// EventOptions configures single-event verification.
type EventOptions struct {
	TenantID                string
	ProjectID               string
	Stream                  string
	Keys                    *integrity.KeySet
	KeySource               string
	RejectedKeys            []integrity.KeyProblem
	RequireCanonicalContent bool
	Verifier                *VerifierInfo
	// Head, when the target is the last event, is compared like in stream
	// verification.
	Head *Head
}

// VerifyEvent verifies one event in its immediate neighbourhood: the event
// itself (canonical content, payload hash, index columns, event hash,
// signature), the link to its predecessor and the link from its successor.
// The neighbours' headers and signatures are verified too, so the target is
// shown to sit between two authentic events.
//
// This is a local check. It proves the event is intact and correctly linked;
// it does not prove that the rest of the stream is intact. Use stream
// verification for that.
func VerifyEvent(target Item, prev, next *Item, opts EventOptions) *Report {
	r := target.Record
	anchor := Anchor{Sequence: r.Sequence - 1, Hash: integrity.ZeroHash, Description: "genesis"}
	var missingPredecessor bool
	items := make([]Item, 0, 3)
	switch {
	case r.Sequence <= 1:
		// The target must link to the genesis value.
	case prev != nil:
		anchor = Anchor{Sequence: prev.Record.Sequence - 1, Hash: prev.Record.PreviousHash,
			Description: fmt.Sprintf("predecessor's link (sequence %d)", prev.Record.Sequence-1)}
		items = append(items, Item{Record: prev.Record.WithoutContent(), Index: nil})
	default:
		missingPredecessor = true
		anchor = Anchor{Sequence: r.Sequence - 1, Hash: r.PreviousHash,
			Description: "the event's own previousHash (predecessor missing)"}
	}
	items = append(items, target)
	if next != nil {
		items = append(items, Item{Record: next.Record.WithoutContent()})
	}

	v := NewStreamVerifier(StreamOptions{
		TenantID:                opts.TenantID,
		ProjectID:               opts.ProjectID,
		Stream:                  opts.Stream,
		Keys:                    opts.Keys,
		KeySource:               opts.KeySource,
		RejectedKeys:            opts.RejectedKeys,
		Anchor:                  &anchor,
		Head:                    opts.Head,
		RequireCanonicalContent: opts.RequireCanonicalContent,
		Scope:                   ScopeEvent,
		Verifier:                opts.Verifier,
		Parallelism:             1,
	})
	if missingPredecessor {
		v.add(Failure{Code: CodeSequenceGap, Sequence: r.Sequence, EventID: r.EventID,
			Message:  fmt.Sprintf("the predecessor (sequence %d) does not exist; it was deleted", r.Sequence-1),
			Expected: fmt.Sprint(r.Sequence - 1), Found: "missing"})
	}
	v.Add(items)
	rep := v.Finish()
	rep.EventID = r.EventID
	if !target.Record.HasContent() {
		rep.Checks.PayloadHashes = StatusSkipped
	}
	return rep
}
