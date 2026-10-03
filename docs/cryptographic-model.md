# Cryptographic model

This document specifies exactly what DƏLİL canonicalizes, hashes and signs
(integrity **schema version 1**), how verification works, and why. It is
written so that someone can build an independent verifier in another language;
[`scripts/verify-test-vectors.mjs`](../scripts/verify-test-vectors.mjs) is
such a verifier, written with nothing but Node.js's standard library.

The reference implementation is [`pkg/integrity`](../pkg/integrity) (formats
and hashing), [`pkg/jcs`](../pkg/jcs) (canonicalization),
[`pkg/verify`](../pkg/verify) (verification) and
[`pkg/evidence`](../pkg/evidence) (evidence packages). None of these packages
does I/O, so they can be audited and reused on their own.

## Summary

```
H(x)            = SHA-256(x)
tagged(t, x)    = H( t ‖ 0x00 ‖ x )                      t is an ASCII tag

payloadHash     = tagged("delil:v1:payload",    JCS(content))
eventHash       = tagged("delil:v1:event",      JCS(header))         header contains payloadHash and previousHash
signature       = Ed25519.Sign(sk, "delil:v1:event-signature" ‖ 0x00 ‖ eventHash)

checkpointHash  = tagged("delil:v1:checkpoint", JCS(checkpointBody))
checkpointSig   = Ed25519.Sign(sk, "delil:v1:checkpoint-signature" ‖ 0x00 ‖ checkpointHash)

manifestHash    = tagged("delil:v1:manifest",   JCS(manifest))
manifestSig     = Ed25519.Sign(sk, "delil:v1:manifest-signature" ‖ 0x00 ‖ manifestHash)

fingerprint     = hex(H(rawPublicKey))                     32-byte Ed25519 public key
keyId           = "ed25519:" ‖ first 32 hex characters of fingerprint
```

Every event of a stream commits to its predecessor through `previousHash`, so
the stream forms a hash chain. The first event (sequence 1) links to 32 zero
bytes. Hashes are written as 64 lowercase hex characters; signatures and public
keys as standard base64.

Only standard primitives are used: SHA-256, Ed25519 (RFC 8032, pure),
AES-256-GCM and HKDF-SHA256 for key wrapping, Argon2id for dashboard passwords.
All of them come from Go's standard library or `golang.org/x/crypto`.

## 1. Canonical JSON (RFC 8785)

Every hashed JSON object is serialized with the JSON Canonicalization Scheme
(JCS, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)):

- object members sorted by the UTF-16 code units of their names;
- strings with the minimal escaping of RFC 8785 §3.2.2.2;
- numbers serialized with ECMAScript's `Number.prototype.toString`
  (§3.2.2.3);
- no insignificant whitespace.

DƏLİL implements JCS itself in `pkg/jcs` so that the canonical form is under
the project's control. The implementation is tested against the RFC's examples,
against about 6,700 numbers serialized by V8's `JSON.stringify`
(`pkg/jcs/testdata`), and for idempotence.

### Strict input profile

Ambiguous input is **rejected, never repaired**. If two different inputs could
canonicalize to the same bytes, an attacker could swap one for the other.

| Rule | Reason |
|---|---|
| UTF-8 only; invalid sequences rejected | Go's `encoding/json` silently replaces them with U+FFFD, which would change data before it is hashed |
| No duplicate member names (I-JSON, RFC 7493) | `{"a":1,"a":2}` means different things to different parsers |
| No unpaired UTF-16 surrogates in `\u` escapes | they have no UTF-8 encoding |
| No U+0000 in strings | PostgreSQL cannot store it reliably |
| Numbers are IEEE-754 binary64; integers beyond ±2^53 rejected; overflow to ±Inf rejected | other languages would round them differently; send large integers as strings |
| Nesting depth ≤ 32 | bounds resource use |

## 2. Event content and header

The **content** is the event as the server stores it, after validation,
redaction and diffing (see [architecture](architecture.md#ingestion)):

```json
{
  "action": "contract.approved",
  "actor": { "displayName": "Sarkhan Mahabbatli", "id": "user_128", "type": "user" },
  "after": { "status": "approved" },
  "before": { "status": "pending" },
  "changes": [ { "from": "pending", "op": "replace", "path": "/status", "to": "approved" } ],
  "context": { "requestId": "req_123", "sourceIp": "203.0.113.7" },
  "metadata": { "requestId": "req_123" },
  "occurredAt": "2026-10-02T09:15:00.000000Z",
  "resource": { "id": "contract_813", "type": "contract" }
}
```

Absent optional members are omitted, never written as `null`. An explicit
`null` for `before`/`after` is meaningful (the resource did not exist / no
longer exists) and is preserved. `redactions` lists the JSON Pointers of
redacted values, so the content itself states that it was redacted.

The **header** binds the content hash to its position:

```json
{
  "eventId": "evt_01J9ZQ4M3F5X8B7K2N6R0T1V3W",
  "keyId": "ed25519:4f8fa19f1b7e0f3f32b130d897aa8a80",
  "payloadHash": "…64 hex…",
  "previousHash": "…64 hex…",
  "projectId": "prj_…",
  "recordedAt": "2026-10-02T09:15:00.123456Z",
  "schemaVersion": 1,
  "sequence": 1842,
  "stream": "contracts",
  "tenantId": "org_…"
}
```

All ten members are required. Timestamps are UTC with exactly six fractional
digits, because PostgreSQL `timestamptz` has microsecond precision and the
value must round-trip byte for byte.

A **record** is the header plus `eventHash`, `signature` and, when disclosed,
`content` (the exact canonical bytes). This is what
`GET /v1/streams/{name}/chain` returns and what evidence packages contain.

### Why this shape

- **Domain separation.** Every hash and signature input starts with a distinct
  tag followed by `0x00`, so a payload hash can never be reinterpreted as an
  event hash, and a checkpoint signature can never pass as an event signature,
  even though one key signs both. The `0x00` byte never occurs inside a tag and
  never occurs unescaped in JCS output, so `(tag, data)` is encoded
  unambiguously.
- **Two-level hashing.** Content → `payloadHash` → header → `eventHash` means
  the chain can be verified from headers alone. Evidence packages use this to
  prove that an event sits in an intact chain without disclosing its neighbours
  (selective disclosure). It also leaves room for future content erasure with
  tombstones.
- **Context binding.** Tenant, project and stream are in the hashed header, so
  an event cannot be moved to another stream or tenant. `keyId` is hashed too,
  which binds the event to the key that signed it.
- **Ed25519, pure.** Deterministic (no per-signature nonce to get wrong), fast
  to verify, and supported by Go, Node.js and the major cloud KMSs. The 32-byte
  `eventHash` is signed with pure Ed25519, not Ed25519ph/ctx, for KMS and HSM
  compatibility; domain separation is done in the message instead.
- **Versioned suite.** The algorithms are fixed by `schemaVersion`. A future
  suite (another hash, a post-quantum signature) is a new schema version, and
  version-1 events keep verifying under version-1 rules.

## 3. Appending

For each event, inside one database transaction that holds a row lock on the
stream:

```
sequence     = head.sequence + 1
previousHash = head.hash                  (32 zero bytes for sequence 1)
recordedAt   = max(now, head.recordedAt)  truncated to microseconds; never decreases within a stream
payloadHash  = tagged("delil:v1:payload", content)
eventHash    = tagged("delil:v1:event", JCS(header))
signature    = Sign(activeKey, "delil:v1:event-signature" ‖ 0x00 ‖ eventHash)
verify the signature with the public key before committing
INSERT the record; move the stream head to (sequence, eventHash)
```

A batch is one transaction: every event is committed, or none is. Database
triggers independently reject an insert whose `previous_hash` is not the
`event_hash` of `sequence − 1`, and any head update that moves backwards. See
[architecture](architecture.md#append-protocol) for the concurrency details.

## 4. Keys

- Each project has exactly one **active** Ed25519 key and any number of
  **retired** or **revoked** keys. Public keys are kept forever, so history
  stays verifiable after rotation.
- `fingerprint = hex(SHA-256(rawPublicKey))`, and `keyId` is `ed25519:` plus
  its first 128 bits. Verifiers recompute both and reject a key record whose id
  does not match its public key (`signing_key_invalid`).
- Each key has a validity window: `activatedAt`, then `retiredAt` (rotation)
  or `revokedAt` (suspected compromise). An event signed by a revoked key with
  `recordedAt` after the revocation **fails** (`signing_key_revoked`). Use
  outside the active window (more than 5 minutes of clock skew) is a warning
  (`signing_key_outside_validity`).
- Private keys never appear in event rows. The `local` provider stores the
  32-byte seed encrypted with AES-256-GCM, under a key derived with HKDF-SHA256
  from `DELIL_MASTER_KEY`. The additional authenticated data binds the
  ciphertext to its key id, tenant and project, so a wrapped key cannot be
  moved to another project. The `file` provider reads PKCS#8 PEM files. See
  [security](security.md#signing-keys).

## 5. Checkpoints

A checkpoint is a signed statement *"stream S of project P had head H at
sequence N"*:

```json
{
  "checkpointId": "chk_…", "createdAt": "2026-10-02T10:00:00.000000Z",
  "headHash": "…", "keyId": "ed25519:…", "projectId": "prj_…",
  "schemaVersion": 1, "sequence": 1000, "stream": "contracts", "tenantId": "org_…"
}
```

The body above is hashed with the `delil:v1:checkpoint` tag. The hash is
signed with the `delil:v1:checkpoint-signature` tag, and both are stored as
`checkpointHash` and `signature`.

Checkpoints are created automatically every `DELIL_CHECKPOINT_EVERY` events
(default 1,000) or when new events are older than `DELIL_CHECKPOINT_MAX_AGE`
(default 1 hour), and on demand. With `DELIL_ANCHOR_DIR` set, each one is also
written once (create-exclusive, never overwritten) to a directory, which should
live on storage the database operators cannot rewrite.

A checkpoint saved **outside** DƏLİL is a **witness**:
`delil checkpoints save` creates one, and `delil verify --witness file.json`
checks it later. If the stream no longer contains exactly that hash at that
sequence, its history was rolled back, truncated or forked. This is the only
way to detect a consistent rollback of the whole database (see the
[threat model](threat-model.md)).

## 6. Verification

`pkg/verify` reads records in ascending sequence order, in batches and with
constant memory, and recomputes everything. The server, the CLI and the offline
evidence verifier all use it.

Per record (in parallel within a batch):

1. `schemaVersion` is supported, and `tenantId`/`projectId`/`stream` equal the
   stream being verified → `unsupported_schema_version`, `context_mismatch`.
2. Content is present when required and parses under the strict profile. In
   database mode it must already be canonical → `payload_missing`,
   `payload_invalid`, `payload_not_canonical`.
3. `tagged(payload, content) = payloadHash` → `payload_hash_mismatch`.
4. In database mode, the denormalized index columns (actor, action, resource,
   occurredAt) equal the signed content → `indexed_field_mismatch`.
5. `tagged(event, JCS(header)) = eventHash` → `event_hash_mismatch`.
6. `keyId` is in the **trusted** key set and valid at `recordedAt` →
   `unknown_signing_key`, `signing_key_invalid`, `signing_key_revoked`.
7. The Ed25519 signature verifies → `signature_invalid`.

In sequence:

8. `sequence = previous + 1` → `sequence_gap`, `sequence_out_of_order`.
9. `previousHash` equals the previous record's **stored** `eventHash`, or the
   anchor (zero hash at genesis, a checkpoint's head for a partial chain) →
   `previous_hash_mismatch`, `anchor_mismatch`.
10. `recordedAt` never decreases → `timestamp_regression`.

After the last record:

11. The stream head recorded outside the chain matches the last record →
    `head_mismatch`. This catches truncation that left the head pointer behind.
12. Every checkpoint and witness has a valid signature and matches the event
    hash at its sequence → `checkpoint_invalid`, `checkpoint_mismatch`. A
    checkpoint beyond the last record means the chain was truncated or rolled
    back → `checkpoint_beyond_head`.

The per-record checks show **which** record was altered. Comparing each link
with the previous record's *stored* hash shows **where** the chain was cut. The
report gives the first failing sequence, every failure (capped at 100, with a
total count), and expected versus found values. It states that events after the
first failure cannot be trusted through the current chain. These failure codes
are a stable, public API.

### Where verification runs matters

| Verifier | Trusts |
|---|---|
| Server (`POST /v1/streams/{name}/verify`, scheduled runs) | the server and its database. A convenience |
| CLI (`delil verify`) | its own copy of `pkg/verify`. It downloads the raw chain; with `--trusted-keys` it does not even trust the server's key list |
| Offline (`delil verify-export`) | only the package and, with `--trusted-keys`, your pinned keys |

## 7. Evidence packages

A ZIP file containing:

| File | Content |
|---|---|
| `manifest.json` | format and version, tenant/project/stream, selection and filters, the covered chain segment and its anchor, the stream head at export time, and the SHA-256 and size of every other file |
| `signature.json` | `{algorithm, keyId, manifestHash, signature}` over `tagged("delil:v1:manifest", JCS(manifest))` |
| `chain.jsonl` | the integrity skeleton: every header in the segment, from the anchor to the last selected event |
| `events.jsonl` | disclosed records: header plus exact canonical content |
| `checkpoints.json` | signed checkpoints used as the anchor or inside the segment |
| `public-keys.json` | every key needed, with fingerprints and validity windows |
| `verification.json` | the server's own check at export time (informational, not trusted) |
| `README.txt` | what the package proves, what it does not, how to verify it |

`delil verify-export` never extracts to disk. It rejects unexpected or
duplicate entries, absolute paths, `..`, symlinks, entries over the size
limits and suspicious compression ratios. It checks every file against the
manifest digests, then verifies the manifest signature, the checkpoints, the
whole skeleton chain from its anchor, and that every disclosed record's content
matches its payload hash and appears in the skeleton (`disclosure_mismatch`,
`selection_mismatch`). Without `--trusted-keys`, the report says that the
keys came from the package itself and must be compared with an independently
obtained copy.

## 8. Test vectors

[`docs/test-vectors.json`](test-vectors.json) contains known-answer vectors:
a fixed key seed, contents with tricky Unicode and numbers, their canonical
forms, payload, event and checkpoint hashes, and signatures. They are checked by
the Go tests (`go test ./pkg/integrity -run TestKnownAnswerVectors`) and
independently by `node scripts/verify-test-vectors.mjs` (`make test-vectors`).
If the two ever disagree, the construction is not reproducible and must not
ship. To regenerate them after an intentional change, which requires a new
schema version, run `go test ./pkg/integrity -run TestKnownAnswerVectors -update`.

## 9. Limits of the construction

- **Tamper evidence, not prevention.** Nothing stops someone with database
  access from changing data. The construction makes the change detectable.
- **The signing key is the root of trust.** Whoever holds a project's private
  key (or the master key plus a database dump) can produce a new, internally
  consistent history. Witnesses, anchors and exported packages held elsewhere
  are what expose such a rewrite. See the [threat model](threat-model.md).
- **`recordedAt` is the server's clock,** forced to be non-decreasing per
  stream. It is not a trusted timestamp. `occurredAt` is whatever the client
  asserted. Trusted time needs external timestamping of checkpoints (RFC 3161,
  on the roadmap).
- **Arrays in diffs are compared as whole values,** to avoid ambiguous
  element-wise diffs.
- **Ordering across streams** is not defined. Each stream is its own chain.
