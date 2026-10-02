package integrity

import (
	"encoding/json"
	"fmt"

	"github.com/serxan22/delil/pkg/jcs"
)

// Actor is who performed the action.
type Actor struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

// Resource is what the action affected.
type Resource struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

// Change is one entry of the structured diff between before and after. Path
// is an RFC 6901 JSON Pointer; From is absent for "add", To is absent for
// "remove".
type Change struct {
	Op   string          `json:"op"`
	Path string          `json:"path"`
	From json.RawMessage `json:"from,omitempty"`
	To   json.RawMessage `json:"to,omitempty"`
}

// RequestContext describes where a request came from.
type RequestContext struct {
	RequestID string `json:"requestId,omitempty"`
	TraceID   string `json:"traceId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	SourceIP  string `json:"sourceIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

// Content is the schema-version-1 event content: the object whose canonical
// form is hashed into payloadHash. Absent optional members are omitted; an
// explicit null in Before or After is meaningful and preserved.
type Content struct {
	Action     string          `json:"action"`
	Actor      Actor           `json:"actor"`
	Resource   *Resource       `json:"resource,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	Changes    []Change        `json:"changes,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	Context    *RequestContext `json:"context,omitempty"`
	OccurredAt string          `json:"occurredAt,omitempty"`
	Redactions []string        `json:"redactions,omitempty"`
}

// ParseContent parses canonical content. The input is validated with the
// strict JCS parser first, so duplicate members and invalid UTF-8 are errors.
// Unknown members are ignored so that newer optional fields do not break
// older readers; they are still covered by the payload hash.
func ParseContent(raw []byte) (*Content, error) {
	if _, err := jcs.Parse(raw); err != nil {
		return nil, fmt.Errorf("integrity: content is not valid JSON: %w", err)
	}
	var c Content
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("integrity: content does not match the event schema: %w", err)
	}
	return &c, nil
}

// IndexFields are the denormalized, queryable columns stored next to each
// event. Verification checks they still agree with the signed content.
type IndexFields struct {
	ActorType    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	OccurredAt   string
}

// Index extracts the index fields from the content.
func (c *Content) Index() IndexFields {
	f := IndexFields{
		ActorType:  c.Actor.Type,
		ActorID:    c.Actor.ID,
		Action:     c.Action,
		OccurredAt: c.OccurredAt,
	}
	if c.Resource != nil {
		f.ResourceType = c.Resource.Type
		f.ResourceID = c.Resource.ID
	}
	return f
}

// Diff lists the index fields that differ between f and other, by name.
func (f IndexFields) Diff(other IndexFields) []string {
	var out []string
	check := func(name, a, b string) {
		if a != b {
			out = append(out, name)
		}
	}
	check("actor_type", f.ActorType, other.ActorType)
	check("actor_id", f.ActorID, other.ActorID)
	check("action", f.Action, other.Action)
	check("resource_type", f.ResourceType, other.ResourceType)
	check("resource_id", f.ResourceID, other.ResourceID)
	check("occurred_at", f.OccurredAt, other.OccurredAt)
	return out
}
