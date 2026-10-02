package verify

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Style decorates text for terminals. The zero value prints plain text.
type Style struct {
	Bold  func(string) string
	Good  func(string) string
	Bad   func(string) string
	Warn  func(string) string
	Muted func(string) string
}

func apply(f func(string) string, s string) string {
	if f == nil {
		return s
	}
	return f(s)
}

// Thousands formats n with comma separators: 18421 -> "18,421".
func Thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

var checkLabels = []struct {
	check Check
	label string
}{
	{CheckHashChain, "Hash chain"},
	{CheckPayloadHashes, "Payload hashes"},
	{CheckSignatures, "Digital signatures"},
	{CheckOrdering, "Ordering"},
	{CheckCheckpoints, "Checkpoints"},
	{CheckStreamHead, "Stream head"},
}

// WriteText renders a human-readable report.
func WriteText(w io.Writer, rep *Report, st Style) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	title := "DƏLİL Integrity Verification"
	switch rep.Scope {
	case ScopeEvent:
		title = "DƏLİL Event Verification"
	case ScopeEvidencePackage:
		title = "DƏLİL Evidence Package Verification"
	}
	p("%s\n\n", apply(st.Bold, title))
	if rep.Stream != "" {
		p("Stream:            %s\n", rep.Stream)
	}
	if rep.EventID != "" {
		p("Event:             %s\n", rep.EventID)
	}
	p("Events checked:    %s\n", Thousands(rep.EventsChecked))
	if rep.EventsChecked > 0 {
		p("First sequence:    %s\n", Thousands(rep.FirstSequence))
		p("Last sequence:     %s\n", Thousands(rep.LastSequence))
	}
	if rep.Anchor != "" && rep.Anchor != "genesis" {
		p("Anchored at:       %s\n", rep.Anchor)
	}
	if rep.KeySource != "" {
		p("Trusted keys:      %s\n", rep.KeySource)
	}
	p("\n")
	for _, cl := range checkLabels {
		s := rep.Checks.Get(cl.check)
		var shown string
		switch s {
		case StatusValid:
			shown = apply(st.Good, "VALID")
		case StatusInvalid:
			shown = apply(st.Bad, "INVALID")
		default:
			shown = apply(st.Muted, "not checked")
		}
		extra := ""
		if cl.check == CheckCheckpoints && rep.CheckpointsVerified > 0 && s != StatusSkipped {
			extra = apply(st.Muted, fmt.Sprintf("  (%d verified)", rep.CheckpointsVerified))
		}
		p("%-19s%s%s\n", cl.label+":", shown, extra)
	}
	p("\n")
	if rep.Valid {
		p("Tampering detected: %s\n\n", apply(st.Good, "NO"))
		for _, w := range rep.Warnings {
			p("%s %s\n", apply(st.Warn, "warning:"), w.String())
		}
		if len(rep.Warnings) > 0 {
			p("\n")
		}
		p("%s\n", apply(st.Good, "Verification completed successfully."))
		return
	}

	p("Tampering detected: %s\n\n", apply(st.Bad, "YES"))
	p("%s\n\n", apply(st.Bad, "Verification FAILED"))
	if ff := rep.FirstFailure; ff != nil {
		if ff.Sequence > 0 {
			p("First invalid event:\n")
			p("  Sequence:  %s\n", Thousands(ff.Sequence))
			if ff.EventID != "" {
				p("  Event ID:  %s\n", ff.EventID)
			}
		}
		p("  Failure:   %s\n", strings.ReplaceAll(string(ff.Code), "_", " "))
		p("  Detail:    %s\n", ff.Message)
		if ff.Expected != "" {
			p("  Expected:  %s\n", ff.Expected)
		}
		if ff.Found != "" {
			p("  Found:     %s\n", ff.Found)
		}
		p("\n")
		if ff.Sequence > 0 && rep.Scope != ScopeEvent {
			p("Events after this point cannot be cryptographically trusted through the current chain.\n\n")
		}
	}
	p("%d failure(s) in total", rep.FailureCount)
	if rep.FailuresTruncated {
		p(" (first %d listed)", len(rep.Failures))
	}
	p(":\n")
	for _, f := range rep.Failures {
		p("  - %s\n", f.String())
	}
	for _, w := range rep.Warnings {
		p("%s %s\n", apply(st.Warn, "warning:"), w.String())
	}
}
