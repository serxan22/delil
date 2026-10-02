package verify

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
)

// DefaultMaxFailures caps the number of failures kept in a report. The total
// is always counted.
const DefaultMaxFailures = 100

// DefaultClockSkew is the tolerance applied to signing-key validity windows.
const DefaultClockSkew = 5 * time.Minute

// reorderWindow is how many recent event hashes are remembered to explain
// broken links ("this event links to sequence 79, not 80").
const reorderWindow = 4096

// Anchor is the trusted starting point of a chain segment: the zero hash at
// sequence 0 for a whole stream, or a checkpointed head for a partial chain.
type Anchor struct {
	Sequence int64
	Hash     integrity.Hash
	// Description is shown in reports, e.g. "genesis" or "checkpoint chk_…".
	Description string
}

// GenesisAnchor anchors a chain at its first event.
func GenesisAnchor() Anchor {
	return Anchor{Sequence: 0, Hash: integrity.ZeroHash, Description: "genesis"}
}

// Head is the stream head recorded outside the chain itself (for example the
// audit_streams row). A mismatch reveals truncation or tampering.
type Head struct {
	Sequence int64
	Hash     integrity.Hash
}

// Item is one record to verify, optionally with the denormalized index
// columns stored next to it in the database.
type Item struct {
	Record integrity.Record
	Index  *integrity.IndexFields
}

// StreamOptions configures stream verification.
type StreamOptions struct {
	TenantID  string
	ProjectID string
	Stream    string
	// Keys is the set of trusted public keys. Records signed by any other key
	// fail with unknown_signing_key.
	Keys *integrity.KeySet
	// KeySource describes where Keys came from ("server", "pinned",
	// "package") and is copied into the report.
	KeySource string
	// RejectedKeys are key records that failed validation (for example a
	// public key that no longer matches its id). Each is reported as a
	// failure; events they signed fail as signed by an untrusted key.
	RejectedKeys []integrity.KeyProblem
	// Anchor is where the segment starts; nil means genesis.
	Anchor *Anchor
	// Head, when set, must equal the last verified record.
	Head *Head
	// Checkpoints are signed checkpoints stored with the stream.
	Checkpoints []integrity.Checkpoint
	// Witnesses are checkpoints obtained independently (for example saved
	// earlier by an auditor). They are checked like checkpoints.
	Witnesses []integrity.Checkpoint
	// RequireContent fails records that carry no content (database mode).
	RequireContent bool
	// RequireCanonicalContent fails content that is not byte-identical to its
	// canonical form (database mode, where the exact bytes are stored).
	RequireCanonicalContent bool
	MaxFailures             int
	Parallelism             int
	ClockSkew               time.Duration
	Scope                   string
	Verifier                *VerifierInfo
	// Now is used for report timestamps; nil means time.Now.
	Now func() time.Time
}

type checkpointRef struct {
	cp      integrity.Checkpoint
	witness bool
	matched bool
}

// StreamVerifier verifies a stream incrementally: feed records in ascending
// sequence order with Add, then call Finish.
type StreamVerifier struct {
	opts   StreamOptions
	anchor Anchor
	report *Report
	start  time.Time

	count       int64
	prevSeq     int64
	prevHash    integrity.Hash
	prevTime    time.Time
	prevTimeSet bool

	keysUsed    map[string]struct{}
	checkpoints map[int64][]*checkpointRef
	allCPs      []*checkpointRef

	recent     map[integrity.Hash]int64
	recentRing []integrity.Hash
	ringPos    int

	hasContent    bool
	checkFailures map[Check]int
}

// NewStreamVerifier prepares a verifier. Checkpoint and witness signatures are
// verified immediately.
func NewStreamVerifier(opts StreamOptions) *StreamVerifier {
	if opts.MaxFailures <= 0 {
		opts.MaxFailures = DefaultMaxFailures
	}
	if opts.Parallelism <= 0 {
		opts.Parallelism = runtime.GOMAXPROCS(0)
	}
	if opts.ClockSkew == 0 {
		opts.ClockSkew = DefaultClockSkew
	}
	if opts.Scope == "" {
		opts.Scope = ScopeStream
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	anchor := GenesisAnchor()
	if opts.Anchor != nil {
		anchor = *opts.Anchor
	}
	v := &StreamVerifier{
		opts:          opts,
		anchor:        anchor,
		start:         opts.Now(),
		prevSeq:       anchor.Sequence,
		prevHash:      anchor.Hash,
		keysUsed:      make(map[string]struct{}),
		checkpoints:   make(map[int64][]*checkpointRef),
		recent:        make(map[integrity.Hash]int64, reorderWindow),
		recentRing:    make([]integrity.Hash, reorderWindow),
		checkFailures: make(map[Check]int),
		report: &Report{
			Object:    "verification_report",
			Scope:     opts.Scope,
			TenantID:  opts.TenantID,
			ProjectID: opts.ProjectID,
			Stream:    opts.Stream,
			Anchor:    anchor.Description,
			KeySource: opts.KeySource,
			Verifier:  opts.Verifier,
			Failures:  []Failure{},
			Warnings:  []Failure{},
			KeysUsed:  []string{},
		},
	}
	for _, kp := range opts.RejectedKeys {
		v.add(Failure{Code: CodeSigningKeyInvalid,
			Message: fmt.Sprintf("signing key record %s is not trustworthy: %s", kp.KeyID, kp.Reason)})
	}
	v.prepareCheckpoints(opts.Checkpoints, false)
	v.prepareCheckpoints(opts.Witnesses, true)
	return v
}

func (v *StreamVerifier) prepareCheckpoints(cps []integrity.Checkpoint, witness bool) {
	label := "checkpoint"
	if witness {
		label = "witness checkpoint"
	}
	for _, cp := range cps {
		switch {
		case cp.TenantID != v.opts.TenantID || cp.ProjectID != v.opts.ProjectID || cp.Stream != v.opts.Stream:
			v.add(Failure{Code: CodeCheckpointInvalid, Sequence: cp.Sequence,
				Message: fmt.Sprintf("%s %s belongs to %s/%s/%s, not to the stream being verified",
					label, cp.CheckpointID, cp.TenantID, cp.ProjectID, cp.Stream)})
			continue
		}
		if err := cp.Verify(v.opts.Keys); err != nil {
			v.add(Failure{Code: CodeCheckpointInvalid, Sequence: cp.Sequence,
				Message: fmt.Sprintf("%s %s cannot be trusted: %v", label, cp.CheckpointID, err)})
			continue
		}
		v.keysUsed[cp.KeyID] = struct{}{}
		ref := &checkpointRef{cp: cp, witness: witness}
		v.allCPs = append(v.allCPs, ref)
		if cp.Sequence == v.anchor.Sequence {
			// The checkpoint describes the anchor itself.
			ref.matched = true
			if !cp.HeadHash.Equal(v.anchor.Hash) {
				v.add(Failure{Code: CodeCheckpointMismatch, Sequence: cp.Sequence,
					Message:  fmt.Sprintf("%s %s disagrees with the anchor of this chain segment", label, cp.CheckpointID),
					Expected: cp.HeadHash.String(), Found: v.anchor.Hash.String()})
			}
			continue
		}
		if cp.Sequence < v.anchor.Sequence {
			// Describes history before the verified segment; nothing to compare.
			ref.matched = true
			continue
		}
		v.checkpoints[cp.Sequence] = append(v.checkpoints[cp.Sequence], ref)
	}
}

// AddFailure records a finding produced outside the engine (for example an
// evidence-package check) so that it is counted and reported uniformly.
func (v *StreamVerifier) AddFailure(f Failure) { v.add(f) }

// add records a failure, applying the severity, category and cap.
func (v *StreamVerifier) add(f Failure) {
	if f.Check == "" {
		f.Check = CheckOf(f.Code)
	}
	if f.Severity == "" {
		f.Severity = SeverityError
	}
	if f.Severity == SeverityWarning {
		if len(v.report.Warnings) < v.opts.MaxFailures {
			v.report.Warnings = append(v.report.Warnings, f)
		}
		return
	}
	v.report.FailureCount++
	v.checkFailures[f.Check]++
	// The first failure is the lowest-sequence invalid event; findings that
	// are not tied to an event only fill the slot until one appears.
	if ff := v.report.FirstFailure; ff == nil || (f.Sequence > 0 && (ff.Sequence == 0 || f.Sequence < ff.Sequence)) {
		ff := f
		v.report.FirstFailure = &ff
	}
	if len(v.report.Failures) < v.opts.MaxFailures {
		v.report.Failures = append(v.report.Failures, f)
	} else {
		v.report.FailuresTruncated = true
	}
}

// recordResult holds the self-contained checks of one record, computed in
// parallel. Failures are grouped so they can be emitted in diagnostic order.
type recordResult struct {
	payload   []Failure
	eventHash []Failure
	signature []Failure
	warnings  []Failure
	recorded  time.Time
	timeOK    bool
}

func (v *StreamVerifier) checkRecord(item *Item) recordResult {
	var res recordResult
	r := &item.Record
	fail := func(dst *[]Failure, code Code, msg, expected, found string) {
		*dst = append(*dst, Failure{Code: code, Sequence: r.Sequence, EventID: r.EventID,
			Message: msg, Expected: expected, Found: found})
	}

	if r.SchemaVersion != integrity.SchemaVersion {
		fail(&res.eventHash, CodeUnsupportedSchema,
			fmt.Sprintf("schema version %d is not supported by this verifier", r.SchemaVersion),
			fmt.Sprint(integrity.SchemaVersion), fmt.Sprint(r.SchemaVersion))
		return res
	}
	if r.TenantID != v.opts.TenantID || r.ProjectID != v.opts.ProjectID || r.Stream != v.opts.Stream {
		fail(&res.eventHash, CodeContextMismatch, "the record belongs to a different tenant, project or stream",
			fmt.Sprintf("%s/%s/%s", v.opts.TenantID, v.opts.ProjectID, v.opts.Stream),
			fmt.Sprintf("%s/%s/%s", r.TenantID, r.ProjectID, r.Stream))
	}

	// Payload: canonical content -> payload hash -> index columns.
	if r.HasContent() {
		canonical, err := jcs.Canonicalize(r.Content)
		switch {
		case err != nil:
			fail(&res.payload, CodePayloadInvalid, fmt.Sprintf("stored content is not valid JSON: %v", err), "", "")
		default:
			if v.opts.RequireCanonicalContent && !bytes.Equal(canonical, r.Content) {
				fail(&res.payload, CodePayloadNotCanonical,
					"stored content is not in RFC 8785 canonical form; its encoding was altered after commit", "", "")
			}
			if got := integrity.PayloadHash(canonical); !got.Equal(r.PayloadHash) {
				fail(&res.payload, CodePayloadHashMismatch,
					"the event content does not match the payload hash committed in the signed header; the content was modified",
					r.PayloadHash.String(), got.String())
			} else if item.Index != nil {
				if content, err := integrity.ParseContent(canonical); err != nil {
					fail(&res.payload, CodePayloadInvalid, err.Error(), "", "")
				} else if diff := content.Index().Diff(*item.Index); len(diff) > 0 {
					want, got := indexValues(content.Index(), *item.Index, diff[0])
					fail(&res.payload, CodeIndexedFieldMismatch,
						fmt.Sprintf("indexed column(s) %v no longer match the signed content", diff), want, got)
				}
			}
		}
	} else if v.opts.RequireContent {
		fail(&res.payload, CodePayloadMissing, "the event content is missing", "", "")
	}

	// Header -> event hash.
	if h, err := r.Header.Hash(); err != nil {
		fail(&res.eventHash, CodeMalformedRecord, fmt.Sprintf("header cannot be hashed: %v", err), "", "")
	} else if !h.Equal(r.EventHash) {
		fail(&res.eventHash, CodeEventHashMismatch,
			"the header fields do not hash to the stored event hash; sequence, timestamps, identifiers or hashes were modified",
			r.EventHash.String(), h.String())
	}

	// Signature over the stored event hash, by a trusted key.
	key, ok := v.opts.Keys.Get(r.KeyID)
	if !ok {
		fail(&res.signature, CodeUnknownSigningKey,
			fmt.Sprintf("signed by key %s, which is not in the trusted key set (forged event, or wrong trusted keys)", r.KeyID), "", r.KeyID)
	} else if !integrity.VerifySignature(key.Ed25519(), integrity.TagEventSignature, r.EventHash, r.Signature) {
		fail(&res.signature, CodeSignatureInvalid,
			fmt.Sprintf("the Ed25519 signature does not verify under key %s", r.KeyID), "", "")
	}

	if t, err := integrity.ParseTime(r.RecordedAt); err == nil {
		res.recorded, res.timeOK = t, true
		if ok {
			switch key.UsageAt(t, v.opts.ClockSkew) {
			case integrity.KeyUsageAfterRevocation:
				fail(&res.signature, CodeSigningKeyRevoked,
					fmt.Sprintf("signed by key %s after it was revoked at %s", r.KeyID, key.RevokedAt), key.RevokedAt, r.RecordedAt)
			case integrity.KeyUsageBeforeActivation:
				res.warnings = append(res.warnings, Failure{Code: CodeKeyOutsideValidity, Severity: SeverityWarning,
					Sequence: r.Sequence, EventID: r.EventID,
					Message: fmt.Sprintf("recorded before key %s was activated (%s)", r.KeyID, key.ActivatedAt)})
			case integrity.KeyUsageAfterRetirement:
				res.warnings = append(res.warnings, Failure{Code: CodeKeyOutsideValidity, Severity: SeverityWarning,
					Sequence: r.Sequence, EventID: r.EventID,
					Message: fmt.Sprintf("recorded after key %s was retired (%s)", r.KeyID, key.RetiredAt)})
			}
		}
	} else {
		fail(&res.eventHash, CodeMalformedRecord, err.Error(), "", r.RecordedAt)
	}
	return res
}

func indexValues(content, stored integrity.IndexFields, field string) (string, string) {
	switch field {
	case "actor_type":
		return content.ActorType, stored.ActorType
	case "actor_id":
		return content.ActorID, stored.ActorID
	case "action":
		return content.Action, stored.Action
	case "resource_type":
		return content.ResourceType, stored.ResourceType
	case "resource_id":
		return content.ResourceID, stored.ResourceID
	case "occurred_at":
		return content.OccurredAt, stored.OccurredAt
	}
	return "", ""
}

// Add verifies a batch of records. Records must arrive in ascending sequence
// order across calls; the engine detects and reports any deviation.
func (v *StreamVerifier) Add(items []Item) {
	if len(items) == 0 {
		return
	}
	results := make([]recordResult, len(items))
	workers := v.opts.Parallelism
	if max := (len(items) + 15) / 16; workers > max {
		workers = max
	}
	if workers <= 1 {
		for i := range items {
			results[i] = v.checkRecord(&items[i])
		}
	} else {
		var wg sync.WaitGroup
		chunk := (len(items) + workers - 1) / workers
		for start := 0; start < len(items); start += chunk {
			end := start + chunk
			if end > len(items) {
				end = len(items)
			}
			wg.Add(1)
			go func(start, end int) {
				defer wg.Done()
				for i := start; i < end; i++ {
					results[i] = v.checkRecord(&items[i])
				}
			}(start, end)
		}
		wg.Wait()
	}
	for i := range items {
		v.sequential(&items[i], &results[i])
	}
}

// sequential runs the order-dependent checks and emits every failure of the
// record in diagnostic order: ordering, linkage, payload, header, signature,
// timestamps.
func (v *StreamVerifier) sequential(item *Item, res *recordResult) {
	r := &item.Record
	expected := v.prevSeq + 1
	if r.Sequence != expected {
		switch {
		case r.Sequence > expected:
			missing := r.Sequence - expected
			v.add(Failure{Code: CodeSequenceGap, Sequence: r.Sequence, EventID: r.EventID,
				Message:  fmt.Sprintf("sequence jumps from %d to %d: %d event(s) are missing", v.prevSeq, r.Sequence, missing),
				Expected: fmt.Sprint(expected), Found: fmt.Sprint(r.Sequence)})
		default:
			v.add(Failure{Code: CodeSequenceOutOfOrder, Sequence: r.Sequence, EventID: r.EventID,
				Message:  fmt.Sprintf("sequence %d appears after sequence %d (duplicate or reordered event)", r.Sequence, v.prevSeq),
				Expected: fmt.Sprint(expected), Found: fmt.Sprint(r.Sequence)})
		}
	}

	if !r.PreviousHash.Equal(v.prevHash) {
		if v.count == 0 {
			v.add(Failure{Code: CodeAnchorMismatch, Sequence: r.Sequence, EventID: r.EventID,
				Message:  fmt.Sprintf("the first event does not link to the chain anchor (%s)", v.anchor.Description),
				Expected: v.prevHash.String(), Found: r.PreviousHash.String()})
		} else {
			msg := fmt.Sprintf("previousHash does not match the event hash of sequence %d; the chain is broken here", v.prevSeq)
			if seq, ok := v.recent[r.PreviousHash]; ok && seq != v.prevSeq {
				msg = fmt.Sprintf("previousHash links to the event at sequence %d instead of %d; events were reordered, removed or inserted",
					seq, v.prevSeq)
			} else if r.PreviousHash.IsZero() {
				msg = "previousHash is the genesis value although this is not the first event; an event was inserted or the chain was rebuilt"
			}
			v.add(Failure{Code: CodePreviousHashMismatch, Sequence: r.Sequence, EventID: r.EventID,
				Message: msg, Expected: v.prevHash.String(), Found: r.PreviousHash.String()})
		}
	}

	for _, group := range [][]Failure{res.payload, res.eventHash, res.signature} {
		for _, f := range group {
			v.add(f)
		}
	}
	for _, w := range res.warnings {
		v.add(w)
	}

	if res.timeOK {
		if v.prevTimeSet && res.recorded.Before(v.prevTime) {
			v.add(Failure{Code: CodeTimestampRegression, Sequence: r.Sequence, EventID: r.EventID,
				Message:  "recordedAt is earlier than the previous event's; timestamps were altered or events reordered",
				Expected: ">= " + integrity.FormatTime(v.prevTime), Found: r.RecordedAt})
		}
		v.prevTime, v.prevTimeSet = res.recorded, true
	}

	if refs := v.checkpoints[r.Sequence]; len(refs) > 0 {
		for _, ref := range refs {
			ref.matched = true
			if !ref.cp.HeadHash.Equal(r.EventHash) {
				label := "checkpoint"
				if ref.witness {
					label = "witness checkpoint"
				}
				v.add(Failure{Code: CodeCheckpointMismatch, Sequence: r.Sequence, EventID: r.EventID,
					Message: fmt.Sprintf("%s %s (created %s) recorded a different event hash at this sequence; history was rewritten after it was taken",
						label, ref.cp.CheckpointID, ref.cp.CreatedAt),
					Expected: ref.cp.HeadHash.String(), Found: r.EventHash.String()})
			}
		}
	}

	if r.HasContent() {
		v.hasContent = true
		v.report.PayloadsChecked++
	}
	if v.count == 0 {
		v.report.FirstSequence = r.Sequence
	}
	v.keysUsed[r.KeyID] = struct{}{}
	v.remember(r.EventHash, r.Sequence)
	v.prevSeq = r.Sequence
	v.prevHash = r.EventHash
	v.count++
}

func (v *StreamVerifier) remember(h integrity.Hash, seq int64) {
	if old := v.recentRing[v.ringPos]; v.count >= reorderWindow {
		delete(v.recent, old)
	}
	v.recentRing[v.ringPos] = h
	v.ringPos = (v.ringPos + 1) % reorderWindow
	v.recent[h] = seq
}

// Finish runs the end-of-stream checks and returns the report.
func (v *StreamVerifier) Finish() *Report {
	rep := v.report
	if v.opts.Head != nil {
		head := v.opts.Head
		switch {
		case v.count == 0 && head.Sequence != v.anchor.Sequence:
			v.add(Failure{Code: CodeHeadMismatch, Sequence: head.Sequence,
				Message:  fmt.Sprintf("the stream head is at sequence %d but no events were found", head.Sequence),
				Expected: fmt.Sprint(head.Sequence), Found: fmt.Sprint(v.anchor.Sequence)})
		case v.count > 0 && head.Sequence > v.prevSeq:
			// Report at the first missing sequence: that is where the chain
			// stops being complete.
			v.add(Failure{Code: CodeHeadMismatch, Sequence: v.prevSeq + 1,
				Message:  fmt.Sprintf("the stream head is at sequence %d but the chain ends at %d: events at the end were removed", head.Sequence, v.prevSeq),
				Expected: fmt.Sprint(head.Sequence), Found: fmt.Sprint(v.prevSeq)})
		case v.count > 0 && head.Sequence < v.prevSeq:
			v.add(Failure{Code: CodeHeadMismatch, Sequence: v.prevSeq,
				Message:  fmt.Sprintf("the chain continues to sequence %d beyond the recorded head %d: events were appended outside the normal path", v.prevSeq, head.Sequence),
				Expected: fmt.Sprint(head.Sequence), Found: fmt.Sprint(v.prevSeq)})
		case !head.Hash.Equal(v.prevHash):
			v.add(Failure{Code: CodeHeadMismatch, Sequence: head.Sequence,
				Message:  "the recorded head hash differs from the hash of the last event",
				Expected: head.Hash.String(), Found: v.prevHash.String()})
		}
	}

	for _, ref := range v.allCPs {
		if ref.matched {
			continue
		}
		label := "checkpoint"
		if ref.witness {
			label = "witness checkpoint"
		}
		if ref.cp.Sequence > v.prevSeq {
			v.add(Failure{Code: CodeCheckpointBeyondHead, Sequence: ref.cp.Sequence,
				Message: fmt.Sprintf("%s %s (created %s) attests sequence %d, but the chain ends at %d: events were removed or the database was rolled back",
					label, ref.cp.CheckpointID, ref.cp.CreatedAt, ref.cp.Sequence, v.prevSeq),
				Expected: fmt.Sprint(ref.cp.Sequence), Found: fmt.Sprint(v.prevSeq)})
		}
	}

	rep.EventsChecked = v.count
	if v.count > 0 {
		rep.LastSequence = v.prevSeq
		rep.LastEventHash = v.prevHash.String()
	}
	for id := range v.keysUsed {
		rep.KeysUsed = append(rep.KeysUsed, id)
	}
	sort.Strings(rep.KeysUsed)
	for _, ref := range v.allCPs {
		if ref.matched {
			rep.CheckpointsVerified++
		}
	}

	status := func(check Check, applicable bool) Status {
		if !applicable {
			return StatusSkipped
		}
		if v.checkFailures[check] > 0 {
			return StatusInvalid
		}
		return StatusValid
	}
	rep.Checks = Checks{
		Package:       v.packageStatus(),
		HashChain:     status(CheckHashChain, true),
		PayloadHashes: status(CheckPayloadHashes, v.hasContent || v.opts.RequireContent),
		Signatures:    status(CheckSignatures, true),
		Ordering:      status(CheckOrdering, true),
		Checkpoints:   status(CheckCheckpoints, len(v.opts.Checkpoints)+len(v.opts.Witnesses) > 0),
		StreamHead:    status(CheckStreamHead, v.opts.Head != nil),
	}
	rep.Valid = rep.FailureCount == 0
	rep.TamperingDetected = !rep.Valid
	rep.Result = ResultValid
	if !rep.Valid {
		rep.Result = ResultInvalid
	}
	end := v.opts.Now()
	rep.StartedAt = integrity.FormatTime(v.start)
	rep.CompletedAt = integrity.FormatTime(end)
	rep.DurationMs = end.Sub(v.start).Milliseconds()
	return rep
}

func (v *StreamVerifier) packageStatus() Status {
	if v.opts.Scope != ScopeEvidencePackage {
		return ""
	}
	if v.checkFailures[CheckPackage] > 0 {
		return StatusInvalid
	}
	return StatusValid
}

// Source yields records in ascending sequence order. An empty batch with a nil
// error ends the stream.
type Source interface {
	Next(ctx context.Context) ([]Item, error)
}

// VerifyStream drains src through a StreamVerifier.
func VerifyStream(ctx context.Context, src Source, opts StreamOptions) (*Report, error) {
	v := NewStreamVerifier(opts)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items, err := src.Next(ctx)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return v.Finish(), nil
		}
		v.Add(items)
	}
}

// SliceSource serves items from memory in batches.
type SliceSource struct {
	Items     []Item
	BatchSize int
	pos       int
}

// Next implements Source.
func (s *SliceSource) Next(context.Context) ([]Item, error) {
	size := s.BatchSize
	if size <= 0 {
		size = 1000
	}
	if s.pos >= len(s.Items) {
		return nil, nil
	}
	end := s.pos + size
	if end > len(s.Items) {
		end = len(s.Items)
	}
	batch := s.Items[s.pos:end]
	s.pos = end
	return batch, nil
}
