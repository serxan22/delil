// Package audit turns API requests into canonical, redacted event content and
// appends it to hash chains.
package audit

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
)

// RequestParseOptions is the strict JSON profile for ingestion: bounded depth,
// numbers that survive binary64 exactly, and no U+0000.
var RequestParseOptions = jcs.Options{MaxDepth: 40, SafeNumbers: true, DisallowNUL: true}

// ReservedStreamPrefix is reserved for streams written by DƏLİL itself.
const ReservedStreamPrefix = "delil."

// EventInput is a decoded event submission. Free-form members are kept as
// parsed JSON trees; the Has* flags distinguish an explicit null from absence.
type EventInput struct {
	Stream     string
	Actor      integrity.Actor
	Action     string
	Resource   *integrity.Resource
	Before     any
	HasBefore  bool
	After      any
	HasAfter   bool
	Data       any
	HasData    bool
	Metadata   map[string]any
	Context    *integrity.RequestContext
	OccurredAt *time.Time
}

// FieldError describes one invalid field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError lists every problem found in a request.
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fe.Field+": "+fe.Message)
	}
	return "invalid event: " + strings.Join(parts, "; ")
}

type errs struct {
	prefix string
	list   []FieldError
}

func (e *errs) add(field, format string, args ...any) {
	e.list = append(e.list, FieldError{Field: e.prefix + field, Message: fmt.Sprintf(format, args...)})
}

func (e *errs) err() error {
	if len(e.list) == 0 {
		return nil
	}
	return &ValidationError{Errors: e.list}
}

var (
	typePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	actionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

// ParseRequestBody parses a request body under RequestParseOptions and
// returns the tree and the SHA-256 of its canonical form (used to recognise
// idempotent retries regardless of formatting).
func ParseRequestBody(body []byte) (any, [32]byte, error) {
	tree, err := jcs.ParseWithOptions(body, RequestParseOptions)
	if err != nil {
		return nil, [32]byte{}, &ValidationError{Errors: []FieldError{{Field: "body", Message: err.Error()}}}
	}
	canonical, err := jcs.Marshal(tree)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return tree, sha256.Sum256(canonical), nil
}

// DecodeEvent converts a parsed tree into an EventInput and validates it.
func DecodeEvent(tree any) (EventInput, error) {
	e := &errs{}
	in := decodeEvent(tree, e)
	return in, e.err()
}

// DecodeBatch decodes {"events": [...]}. Field names in errors carry the
// index, e.g. "events[3].actor.id".
func DecodeBatch(tree any, maxEvents int) ([]EventInput, error) {
	e := &errs{}
	m, ok := tree.(map[string]any)
	if !ok {
		e.add("body", "must be a JSON object with an \"events\" array")
		return nil, e.err()
	}
	for k := range m {
		if k != "events" {
			e.add(k, "unknown field")
		}
	}
	list, ok := m["events"].([]any)
	switch {
	case !ok:
		e.add("events", "is required and must be an array")
		return nil, e.err()
	case len(list) == 0:
		e.add("events", "must contain at least one event")
		return nil, e.err()
	case len(list) > maxEvents:
		e.add("events", "must contain at most %d events", maxEvents)
		return nil, e.err()
	}
	out := make([]EventInput, 0, len(list))
	for i, item := range list {
		e.prefix = fmt.Sprintf("events[%d].", i)
		out = append(out, decodeEvent(item, e))
	}
	return out, e.err()
}

var eventFields = map[string]bool{
	"stream": true, "actor": true, "action": true, "resource": true, "before": true, "after": true,
	"data": true, "metadata": true, "context": true, "occurredAt": true,
}

func decodeEvent(tree any, e *errs) EventInput {
	var in EventInput
	m, ok := tree.(map[string]any)
	if !ok {
		e.add("body", "an event must be a JSON object")
		return in
	}
	for _, k := range sortedKeys(m) {
		if !eventFields[k] {
			e.add(k, "unknown field")
		}
	}

	in.Stream = requiredString(m, "stream", e)
	if in.Stream != "" {
		switch {
		case !integrity.ValidStreamName(in.Stream):
			e.add("stream", "must match ^[a-z0-9][a-z0-9._-]{0,63}$")
		case strings.HasPrefix(in.Stream, ReservedStreamPrefix):
			e.add("stream", "the %q prefix is reserved", ReservedStreamPrefix)
		}
	}

	if actor, ok := object(m, "actor", true, e); ok {
		in.Actor = integrity.Actor{
			Type:        identifier(actor, "actor.", "type", typePattern, true, e),
			ID:          text(actor, "actor.", "id", 256, true, e),
			DisplayName: text(actor, "actor.", "displayName", 256, false, e),
		}
		unknown(actor, "actor.", e, "type", "id", "displayName")
	}

	in.Action = requiredString(m, "action", e)
	if in.Action != "" && !actionPattern.MatchString(in.Action) {
		e.add("action", "must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
	}

	if res, ok := object(m, "resource", false, e); ok {
		in.Resource = &integrity.Resource{
			Type:        identifier(res, "resource.", "type", typePattern, true, e),
			ID:          text(res, "resource.", "id", 256, true, e),
			DisplayName: text(res, "resource.", "displayName", 256, false, e),
		}
		unknown(res, "resource.", e, "type", "id", "displayName")
	}

	in.Before, in.HasBefore = m["before"]
	in.After, in.HasAfter = m["after"]
	in.Data, in.HasData = m["data"]

	if md, present := m["metadata"]; present {
		obj, ok := md.(map[string]any)
		if !ok {
			e.add("metadata", "must be a JSON object")
		} else {
			in.Metadata = obj
		}
	}

	if ctx, ok := object(m, "context", false, e); ok {
		rc := &integrity.RequestContext{
			RequestID: text(ctx, "context.", "requestId", 128, false, e),
			TraceID:   text(ctx, "context.", "traceId", 128, false, e),
			SessionID: text(ctx, "context.", "sessionId", 128, false, e),
			UserAgent: text(ctx, "context.", "userAgent", 512, false, e),
		}
		if ip := text(ctx, "context.", "sourceIp", 64, false, e); ip != "" {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				e.add("context.sourceIp", "must be an IPv4 or IPv6 address")
			} else {
				rc.SourceIP = addr.Unmap().String()
			}
		}
		unknown(ctx, "context.", e, "requestId", "traceId", "sessionId", "userAgent", "sourceIp")
		if *rc != (integrity.RequestContext{}) {
			in.Context = rc
		}
	}

	if raw, present := m["occurredAt"]; present {
		s, ok := raw.(string)
		if !ok {
			e.add("occurredAt", "must be an RFC 3339 timestamp string")
		} else {
			t, err := time.Parse(time.RFC3339Nano, s)
			switch {
			case err != nil:
				e.add("occurredAt", "must be an RFC 3339 timestamp, e.g. 2026-10-02T09:15:00Z")
			case t.Year() < 1970 || t.Year() > 9999:
				e.add("occurredAt", "is out of range")
			default:
				u := t.UTC().Truncate(time.Microsecond)
				in.OccurredAt = &u
			}
		}
	}
	return in
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func unknown(m map[string]any, prefix string, e *errs, allowed ...string) {
	ok := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	for _, k := range sortedKeys(m) {
		if !ok[k] {
			e.add(prefix+k, "unknown field")
		}
	}
}

func object(m map[string]any, name string, required bool, e *errs) (map[string]any, bool) {
	raw, present := m[name]
	if !present {
		if required {
			e.add(name, "is required")
		}
		return nil, false
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		e.add(name, "must be a JSON object")
		return nil, false
	}
	return obj, true
}

func requiredString(m map[string]any, name string, e *errs) string {
	raw, present := m[name]
	if !present {
		e.add(name, "is required")
		return ""
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		e.add(name, "must be a non-empty string")
		return ""
	}
	return s
}

func identifier(m map[string]any, prefix, name string, re *regexp.Regexp, required bool, e *errs) string {
	s := text(m, prefix, name, 64, required, e)
	if s != "" && !re.MatchString(s) {
		e.add(prefix+name, "must match %s", re.String())
		return ""
	}
	return s
}

func text(m map[string]any, prefix, name string, max int, required bool, e *errs) string {
	raw, present := m[name]
	if !present {
		if required {
			e.add(prefix+name, "is required")
		}
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		e.add(prefix+name, "must be a string")
		return ""
	}
	if required && strings.TrimSpace(s) == "" {
		e.add(prefix+name, "must not be empty")
		return ""
	}
	if utf8.RuneCountInString(s) > max {
		e.add(prefix+name, "must be at most %d characters", max)
		return ""
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			e.add(prefix+name, "must not contain control characters")
			return ""
		}
	}
	return s
}
