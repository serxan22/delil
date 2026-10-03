# Threat model

DƏLİL makes changes to recorded audit events **detectable**. This document
says against whom, under which assumptions, and where detection stops. Read it
together with the [cryptographic model](cryptographic-model.md).

## What is protected

| Asset | Property |
|---|---|
| Committed audit events (content and order) | integrity: any modification, insertion, deletion, reordering or truncation is detected by verification |
| Signing keys (Ed25519 private keys) | confidentiality: they are the root of trust for authenticity |
| Master key (`DELIL_MASTER_KEY`) | confidentiality: it unwraps every locally stored signing key |
| Event content | confidentiality between tenants and projects; minimisation via redaction ([privacy](privacy.md)) |
| API keys, session tokens, passwords | confidentiality: only hashes are stored |
| Verification results | correctness: must not report "valid" for tampered data |

**Not** protected: the truth of what applications report. DƏLİL proves that a
record has not changed since it was committed, not that the application told
the truth when it sent it. `occurredAt` is asserted by the client, and
`recordedAt` comes from the server's clock.

## Trust boundaries

```
 application ──(TLS, API key)──► delil-server ──(SQL, delil_app role)──► PostgreSQL
                                     │  ▲
                        signing keys │  │ master key (env / file / secret manager)
                                     ▼  │
 auditor ◄── evidence package (ZIP, offline) ◄── exports
 auditor ──(TLS, read key)──► raw chain ──► delil verify (local, pinned keys, witnesses)
 witness storage (WORM / another host / the auditor) ◄── checkpoints
```

The auditor's machine, the pinned `trusted-keys.json`, and the witnesses are
assumed to be outside the reach of whoever attacks the server.

## Adversaries and outcomes

| Adversary | Capability | Can they tamper without detection? |
|---|---|---|
| Application client with an API key | append events within its scopes | **No.** The API has no update or delete; past events are immutable. A malicious client can append false events, attributed to its key. |
| Network attacker | observe and modify traffic | **No**, with TLS in front of the server. Records are self-authenticating (signed), so modified records fail verification even without TLS. |
| Attacker with database write access, no signing key (DBA, SQL injection, stolen backup restored elsewhere) | modify, insert, delete rows; bypass triggers | **No** for any change *inside* the chain: content, header, order, insertion and deletion all break hashes, links or signatures. **Tail truncation** that also rewinds the head pointer and deletes later checkpoints is detected only by a **witness** or an **anchored** checkpoint. **Rolling back the whole database** to an earlier consistent backup is likewise only detected by witnesses. |
| Attacker with database access **and** a signing key (or the master key plus a dump) | everything above, plus re-signing | **Yes**, for any history not covered by an external witness, anchor or exported package. They can rebuild a consistent chain. Mitigations: protect keys (separate secret store, `file` provider on a restricted mount, KMS/HSM on the roadmap), rotate, keep witnesses and anchors outside their reach, and export regularly. |
| Compromised running server | full control of the process | Can sign arbitrary **new** events, drop or alter incoming ones before signing, and lie in server-side verification results. **Cannot** alter already-witnessed history without detection, and cannot fool the CLI or offline verifier when keys are pinned. |
| Compromised dashboard (Next.js) | acts as a logged-in user | Limited to that user's role. It never holds API keys. Its server-side requests carry the user's session token. |
| Malicious tenant | uses its own credentials | **No** access to other tenants. Every query is scoped by tenant and project from the authenticated principal, and other tenants' objects return 404. Covered by dedicated tests. |
| Attacker who crafts evidence packages | sends a ZIP to an auditor | Cannot make a modified package verify. The verifier rejects zip-slip, symlinks, duplicates, oversized entries and suspicious compression ratios, and never extracts to disk. **Keys:** without `--trusted-keys`, a forged package signed by the forger's own key verifies *as self-consistent*, and the report says the keys came from the package. Always pin keys. |
| Clock manipulation on the server | sets the system time | `recordedAt` cannot go backwards within a stream (it is clamped to the head's value), but forward or backward drift goes unnoticed. `recordedAt` is not trusted time. |

## Attack catalogue

| Attack | Detected by | Failure code |
|---|---|---|
| Edit an event's content (directly in SQL) | payload hash | `payload_hash_mismatch` |
| Edit content and recompute its payload hash | header hash | `event_hash_mismatch` |
| Edit content, payload hash and event hash | signature | `signature_invalid` |
| Edit only the filterable index columns (`actor_id`, `action`, …) | content/index comparison | `indexed_field_mismatch` |
| Change the actor or timestamp in the content | as content edits | `payload_hash_mismatch` |
| Delete an event | sequence and link | `sequence_gap`, `previous_hash_mismatch` |
| Insert a forged event | link and signature | `previous_hash_mismatch`, `signature_invalid` / `unknown_signing_key` |
| Swap or reorder two events | links, order and timestamps | `previous_hash_mismatch`, `sequence_out_of_order`, `timestamp_regression` |
| Move an event to another stream or tenant | context in the hashed header | `context_mismatch` |
| Truncate the tail, leave the head pointer | head check | `head_mismatch` |
| Truncate the tail and rewind the head pointer | stored checkpoints, then witnesses | `checkpoint_beyond_head` / `checkpoint_mismatch` |
| … and delete the stored checkpoints | **witness or anchor only** | `checkpoint_beyond_head` (witness) |
| Restore an older consistent backup (rollback) | **witness or anchor only** | `checkpoint_beyond_head` |
| Replace the stored public key | key-id derivation; pinned keys | `signing_key_invalid`, `unknown_signing_key` |
| Sign with a revoked key after revocation | key validity window | `signing_key_revoked` |
| Edit an exported package | file digests and manifest signature | `package_digest_mismatch`, `manifest_signature_invalid` |
| Disclose content that is not in the chain | skeleton membership | `disclosure_mismatch` |
| Ambiguous JSON (duplicate keys, invalid UTF-8, huge integers) | rejected at ingestion and verification | `payload_invalid` |

`internal/verification/tamper_test.go` reproduces these scenarios against a
real PostgreSQL database, and CI's end-to-end job edits a record in the running
Compose stack and requires the CLI to report it.

## Defence in depth for stored records

1. The API exposes no update or delete for events or checkpoints.
2. Triggers reject `UPDATE`, `DELETE` and `TRUNCATE` on `audit_events` and
   `checkpoints`, and reject inserts that do not link to their predecessor.
   They stop bugs and accidents, **not** a superuser or table owner, who can
   disable triggers (the tamper demo does exactly that).
3. The server runs as a least-privilege role (`delil_app`) with only `SELECT`
   and `INSERT` on audit tables. Migrations run as a separate owner role.
4. **Cryptographic verification is the control that detects tampering by
   anyone,** including superusers. Points 1 to 3 only make tampering harder.

## Assumptions

- SHA-256 is collision- and second-preimage-resistant. Ed25519 signatures are
  existentially unforgeable.
- Verifiers run trustworthy code (build the CLI from source or check the
  release provenance) and obtain trusted keys out of band.
- Witnesses and anchored checkpoints are stored where the attacker cannot
  modify them.
- TLS terminates in front of the server in production, and the master key is
  provided by a secret manager, not committed or baked into images.
- The host running `delil-server` is not compromised. If it is, see "Compromised
  running server" above.

## Residual risks and roadmap

| Risk | Current mitigation | Planned |
|---|---|---|
| Key and database compromised together | key custody, rotation, external witnesses | KMS/HSM and remote-signer providers |
| Rollback without witnesses | file anchors, `delil checkpoints save` | RFC 3161 timestamping and transparency-log anchoring |
| No trusted time | `recordedAt` monotonic per stream | RFC 3161 timestamps on checkpoints |
| Personal data cannot be erased from an immutable chain | redaction, `retainStates: diff`, pseudonymous identifiers | content erasure with tombstones (the two-level hash already allows it) |
| A malicious client can log false events | API key scopes, per-key attribution | out of scope: DƏLİL records claims, it does not validate them |

Report weaknesses in this model privately: see [SECURITY.md](../SECURITY.md).
