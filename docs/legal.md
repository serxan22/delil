# Legal considerations

*Dəlil* means "evidence" in Azerbaijani. This page explains what DƏLİL's
records and evidence packages can and cannot demonstrate, so that lawyers,
auditors and courts can weigh them correctly. **It is not legal advice.**
Whether a record is admissible, and how much weight it carries, depends on the
jurisdiction, the procedure and the facts. Consult a qualified lawyer.

## What a verified record demonstrates

When `delil verify` or `delil verify-export` reports **VALID** with pinned keys,
it establishes, under the assumptions in the [threat model](threat-model.md):

1. **Integrity**: the content of each checked event is byte-for-byte what was
   committed, and no event in the checked range was modified, inserted, removed
   or reordered since it was signed.
2. **Origin**: each event was signed by a key that belongs to the identified
   DƏLİL project, as shown by the public key and its fingerprint.
3. **Sequence**: the events were committed in the stated order within their
   stream, and the server's `recordedAt` times never decrease.
4. **Completeness of a range**: with a checkpoint or witness covering the range,
   no event inside it is missing.

When verification **fails**, the report identifies the first affected sequence
and the nature of the change. That is itself evidence of tampering or
corruption.

## What it does not demonstrate

- **That the content is true.** DƏLİL proves that a record was not changed
  after it was committed. It does not prove that the application, or the person
  using it, reported events truthfully.
- **Who the human actor was.** `actor` is what the application asserted. Its
  reliability depends on the application's authentication.
- **Trusted time.** `recordedAt` comes from the server's clock, and
  `occurredAt` from the client. Neither is a qualified or trusted timestamp
  (such as RFC 3161 from a trust service provider). Anchoring checkpoints with
  a timestamping authority is on the roadmap.
- **Protection against the key holder.** Whoever controls a project's signing
  key and its database can create an alternative, internally consistent history
  for periods not covered by independent witnesses or previously exported
  packages. Who held the keys, and how they were protected, is part of the
  factual record a court may examine.
- **Legal status of the signatures.** DƏLİL's Ed25519 signatures are produced
  by a server key, not by a natural person with a qualified certificate. Under
  frameworks such as the EU eIDAS Regulation or Azerbaijan's law on electronic
  signatures and electronic documents, they are at most simple electronic
  signatures or seals, not qualified ones, and do not carry the legal
  presumptions attached to qualified signatures, seals or time stamps.

Every evidence package states this in its manifest notice and `README.txt`.

## Supporting admissibility in practice

Courts and regulators typically ask whether electronic evidence is
**authentic**, **intact**, and **reliably produced**, and how it was handled
(**chain of custody**). DƏLİL addresses integrity directly. You can strengthen
the rest:

| Question | What helps |
|---|---|
| Is the system reliable? | The open-source code, CI results, the published cryptographic model and test vectors, and release provenance for the exact version in use |
| Who controlled the keys? | A key-custody record: provider, who had access, rotations, revocations (all visible in `signing_keys`) |
| Has the record been handled properly since export? | The package's SHA-256 recorded at export, transfer logs, and the package itself, which verifies offline at any time |
| Could the operator have rewritten history? | Witnesses held by independent parties (auditors, counterparties), anchored checkpoints on WORM storage, regular exports |
| Can someone else check it? | Yes: `delil verify-export` is open source and needs no access to the operator's systems; `docs/test-vectors.json` lets anyone build an independent verifier |

For incident or litigation work, follow recognized digital-evidence practice
(for example ISO/IEC 27037 for identification, collection, acquisition and
preservation). Export the relevant range early, record the package hash in your
case file, and keep the trusted-keys file obtained independently of the
package.

## Data protection

Audit logs contain personal data. Retention, legal basis, erasure and
disclosure are covered in [privacy](privacy.md).

## License

DƏLİL is licensed under the [Apache License 2.0](../LICENSE), which includes a
disclaimer of warranty and a limitation of liability (sections 7 and 8). Using
DƏLİL does not by itself make an organization compliant with any law or
standard.
