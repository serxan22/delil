package id

import (
	"sort"
	"testing"
	"time"
)

func TestNewAndValid(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		v := New(Event)
		if !Valid(Event, v) {
			t.Fatalf("generated invalid id %q", v)
		}
		if seen[v] {
			t.Fatalf("duplicate id %q", v)
		}
		seen[v] = true
	}
	for _, bad := range []string{"", "evt_", "evt_01J9ZQ4M3F5X8B7K2N6R0T1V3", "prj_01J9ZQ4M3F5X8B7K2N6R0T1V3W",
		"evt_01J9ZQ4M3F5X8B7K2N6R0T1V3I", "evt-01J9ZQ4M3F5X8B7K2N6R0T1V3W"} {
		if Valid(Event, bad) {
			t.Errorf("Valid(%q) should be false", bad)
		}
	}
}

func TestULIDSortsByTime(t *testing.T) {
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 50; i++ {
		ids = append(ids, ulid(base.Add(time.Duration(i)*time.Millisecond)))
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("ULIDs must sort by timestamp")
	}
	if got := ulid(time.UnixMilli(0))[:10]; got != "0000000000" {
		t.Fatalf("epoch timestamp prefix: %s", got)
	}
}
