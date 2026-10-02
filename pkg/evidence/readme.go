package evidence

import (
	"fmt"
	"strings"
)

// Readme renders README.txt for a package.
func Readme(m *Manifest) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("DƏLİL EVIDENCE PACKAGE\n")
	w("======================\n\n")
	w("Package:      %s\n", m.PackageID)
	w("Created:      %s\n", m.CreatedAt)
	w("Generator:    %s %s\n", m.Generator.Name, m.Generator.Version)
	w("Organization: %s (%s)\n", m.Tenant.Name, m.Tenant.ID)
	w("Project:      %s (%s)\n", m.Project.Name, m.Project.ID)
	w("Stream:       %s\n", m.Stream)
	w("Selection:    sequences %d to %d", m.Selection.FromSequence, m.Selection.ToSequence)
	if m.Selection.RecordedFrom != "" || m.Selection.RecordedTo != "" {
		w(" (recorded %s to %s)", orAny(m.Selection.RecordedFrom), orAny(m.Selection.RecordedTo))
	}
	w("\n")
	if len(m.Selection.Filters) > 0 {
		var parts []string
		for k, v := range m.Selection.Filters {
			parts = append(parts, k+"="+v)
		}
		w("Filters:      %s\n", strings.Join(parts, ", "))
	}
	w("Disclosed:    %d event(s) with content\n", m.Selection.DisclosedEvents)
	w("Chain:        %d header(s), sequences %d to %d, anchored at %s\n\n",
		m.Chain.Events, m.Chain.FirstSequence, m.Chain.LastSequence, m.Chain.Anchor.Type)

	w(`WHAT THIS PACKAGE PROVES

If verification succeeds, every disclosed event is byte-for-byte the event
that was committed, and no event in the covered chain segment was altered,
removed, inserted or reordered after it was committed: every event is
SHA-256 hashed, linked to its predecessor and signed with Ed25519, and the
segment is linked to a signed starting point (the stream's genesis or a
signed checkpoint).

WHAT IT DOES NOT PROVE

- Who produced it, unless you verify with public keys obtained independently
  of this package (see "Trust" below).
- That the events are true. DƏLİL proves records were not changed after they
  were committed; it cannot know whether the application told the truth.
- When events happened. recordedAt is the server's clock and occurredAt is
  asserted by the application; neither is a trusted timestamp.
- Legal admissibility. That depends on the applicable law and procedure.

FILES

  manifest.json      what the package covers and the SHA-256 of every file
  signature.json     Ed25519 signature over the canonical manifest
  chain.jsonl        one event header per line, from the anchor to the last
                     selected event; proves the chain is complete
  events.jsonl       the disclosed events, with their exact canonical content
  checkpoints.json   signed checkpoints (the anchor, and any inside the range)
  public-keys.json   the Ed25519 public keys used
  verification.json  the producing server's own verification (informational)

VERIFY

  delil verify-export <this-file>.zip
  delil verify-export <this-file>.zip --trusted-keys trusted-keys.json

TRUST

The keys in public-keys.json only show that the package is internally
consistent. To know who signed it, compare their fingerprints with keys you
obtained separately (for example "delil keys export" run by your own team, or
fingerprints published by the organization), or pass them with
--trusted-keys.

VERIFYING WITHOUT DƏLİL

The construction uses only public standards: RFC 8785 (JSON
Canonicalization Scheme), SHA-256 and Ed25519 (RFC 8032).

  payloadHash = SHA-256("delil:v1:payload" || 0x00 || JCS(content))
  eventHash   = SHA-256("delil:v1:event" || 0x00 || JCS(header))
  signature   = Ed25519("delil:v1:event-signature" || 0x00 || eventHash)

The header is every member of a chain.jsonl line except eventHash and
signature. Each event's previousHash equals the eventHash of the event
before it. The full specification and test vectors are published with
DƏLİL (docs/cryptographic-model.md, docs/test-vectors.json).
`)
	w("\nNOTICE\n\n%s\n", m.Notice)
	return b.String()
}

func orAny(s string) string {
	if s == "" {
		return "(open)"
	}
	return s
}
