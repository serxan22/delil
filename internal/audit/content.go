package audit

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/serxan22/delil/pkg/integrity"
	"github.com/serxan22/delil/pkg/jcs"
)

// ErrEventTooLarge means the canonical content exceeds the size limit.
var ErrEventTooLarge = errors.New("event content exceeds the maximum size")

// Prepared is an event ready to be appended: its canonical content and the
// values of the index columns.
type Prepared struct {
	Stream     string
	Content    []byte
	Index      integrity.IndexFields
	OccurredAt *time.Time
}

// Prepare redacts, diffs and canonicalizes an event. maxBytes bounds the
// canonical content size.
func Prepare(in EventInput, settings Settings, maxBytes int) (Prepared, error) {
	if settings.MaxEventBytes > 0 && settings.MaxEventBytes < maxBytes {
		maxBytes = settings.MaxEventBytes
	}
	red := NewRedactor(settings.Redaction)
	redactions := map[string]bool{}
	note := func(paths []string) {
		for _, p := range paths {
			redactions[p] = true
		}
	}

	content := map[string]any{
		"action": in.Action,
		"actor":  actorTree(in.Actor),
	}
	if in.Resource != nil {
		content["resource"] = resourceTree(*in.Resource)
	}

	// The diff is computed on copies of the unredacted states so that a
	// change to a sensitive member is still visible (with redacted values).
	diffMode := settings.RetainStates == RetainDiff
	if (in.HasBefore && in.HasAfter) || (diffMode && (in.HasBefore || in.HasAfter)) {
		var before, after any
		if in.HasBefore {
			before = DeepCopy(in.Before)
		}
		if in.HasAfter {
			after = DeepCopy(in.After)
		}
		changes := Diff(before, after)
		if len(changes) > 0 {
			list := make([]any, 0, len(changes))
			for i := range changes {
				note(red.RedactChange(&changes[i]))
				list = append(list, changes[i].Tree())
			}
			content["changes"] = list
		} else if diffMode {
			content["changes"] = []any{}
		}
	}

	if in.HasBefore && !diffMode {
		v, paths := red.Apply("/before", DeepCopy(in.Before))
		note(paths)
		content["before"] = v
	}
	if in.HasAfter && !diffMode {
		v, paths := red.Apply("/after", DeepCopy(in.After))
		note(paths)
		content["after"] = v
	}
	if in.HasData {
		v, paths := red.Apply("/data", DeepCopy(in.Data))
		note(paths)
		content["data"] = v
	}
	if in.Metadata != nil {
		v, paths := red.Apply("/metadata", DeepCopy(in.Metadata))
		note(paths)
		content["metadata"] = v
	}
	if in.Context != nil {
		content["context"] = contextTree(*in.Context)
	}
	var occurred string
	if in.OccurredAt != nil {
		occurred = integrity.FormatTime(*in.OccurredAt)
		content["occurredAt"] = occurred
	}
	if len(redactions) > 0 {
		list := make([]string, 0, len(redactions))
		for p := range redactions {
			list = append(list, p)
		}
		sort.Strings(list)
		content["redactions"] = list
	}

	canonical, err := jcs.Marshal(content)
	if err != nil {
		return Prepared{}, fmt.Errorf("canonicalize event: %w", err)
	}
	if len(canonical) > maxBytes {
		return Prepared{}, fmt.Errorf("%w: %d bytes (limit %d)", ErrEventTooLarge, len(canonical), maxBytes)
	}
	idx := integrity.IndexFields{
		ActorType:  in.Actor.Type,
		ActorID:    in.Actor.ID,
		Action:     in.Action,
		OccurredAt: occurred,
	}
	if in.Resource != nil {
		idx.ResourceType, idx.ResourceID = in.Resource.Type, in.Resource.ID
	}
	return Prepared{Stream: in.Stream, Content: canonical, Index: idx, OccurredAt: in.OccurredAt}, nil
}

func actorTree(a integrity.Actor) map[string]any {
	m := map[string]any{"type": a.Type, "id": a.ID}
	if a.DisplayName != "" {
		m["displayName"] = a.DisplayName
	}
	return m
}

func resourceTree(r integrity.Resource) map[string]any {
	m := map[string]any{"type": r.Type, "id": r.ID}
	if r.DisplayName != "" {
		m["displayName"] = r.DisplayName
	}
	return m
}

func contextTree(c integrity.RequestContext) map[string]any {
	m := map[string]any{}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("requestId", c.RequestID)
	set("traceId", c.TraceID)
	set("sessionId", c.SessionID)
	set("sourceIp", c.SourceIP)
	set("userAgent", c.UserAgent)
	return m
}
