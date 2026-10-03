package audit

import (
	"reflect"
	"sort"
)

// Diff operations.
const (
	OpAdd     = "add"
	OpRemove  = "remove"
	OpReplace = "replace"
)

// Change is one diff entry as stored in event content.
type Change struct {
	Op   string
	Path string
	From any
	To   any
}

// Tree renders the change as a content tree.
func (c Change) Tree() map[string]any {
	m := map[string]any{"op": c.Op, "path": c.Path}
	if c.Op != OpAdd {
		m["from"] = c.From
	}
	if c.Op != OpRemove {
		m["to"] = c.To
	}
	return m
}

// Diff computes a structured, deterministic diff between two JSON trees.
//
// Objects are compared member by member, recursively. Arrays and scalars are
// compared as whole values, which keeps diffs unambiguous at the cost of
// coarser changes for edited lists. At the root, null is treated as an empty
// object, so creating a resource (before = null) yields one "add" per
// member and deleting one (after = null) yields one "remove" per member.
// Paths are RFC 6901 JSON Pointers; the result is sorted by path.
func Diff(before, after any) []Change {
	var out []Change
	b, a := before, after
	_, bObj := before.(map[string]any)
	_, aObj := after.(map[string]any)
	if before == nil && aObj {
		b = map[string]any{}
	}
	if after == nil && bObj {
		a = map[string]any{}
	}
	diffValue("", b, a, &out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func diffValue(path string, before, after any, out *[]Change) {
	if reflect.DeepEqual(before, after) {
		return
	}
	bm, bObj := before.(map[string]any)
	am, aObj := after.(map[string]any)
	if !bObj || !aObj {
		*out = append(*out, Change{Op: OpReplace, Path: path, From: before, To: after})
		return
	}
	keys := make(map[string]struct{}, max(len(bm), len(am)))
	for k := range bm {
		keys[k] = struct{}{}
	}
	for k := range am {
		keys[k] = struct{}{}
	}
	for k := range keys {
		child := path + "/" + escapePointer(k)
		bv, inBefore := bm[k]
		av, inAfter := am[k]
		switch {
		case inBefore && !inAfter:
			*out = append(*out, Change{Op: OpRemove, Path: child, From: bv})
		case !inBefore && inAfter:
			*out = append(*out, Change{Op: OpAdd, Path: child, To: av})
		default:
			diffValue(child, bv, av, out)
		}
	}
}
