# DƏLİL — Initial Architecture (design gate)

Status: **accepted** for v0.1.0 · Date: 2026-10-02

This document settles the decisions that must be right *before* code is written:
the cryptographic construction, canonicalization, the database concurrency model,
the signing strategy, multi-tenancy, key rotation, the verification procedure and
the threat-model assumptions. Later documents (`architecture.md`,
`cryptographic-model.md`, `threat-model.md`, …) describe the implemented system in
more depth; where they disagree with this file, the implementation documents win and
this file should be amended.

---

## 1. Decision summary

| Topic | Decision |
|---|---|
| Backend language | Go 1.27 (single static binaries for server and CLI) |
| Database | PostgreSQL ≥ 16 (developed against 18) — the only stateful dependency |
| Canonicalization | RFC 8785 JSON Canonicalization Scheme (JCS), strict I-JSON input profile |
| Hash | SHA-256 with ASCII domain-separation tags |
| Signature | Ed25519 (RFC 8032, pure EdDSA) over a domain-separated message containing the event hash |
| Chain | Per-stream linear hash chain; `previousHash` of sequence 1 is 32 zero bytes |
| Concurrency | One transaction per append; the stream row is locked with `SELECT … FOR UPDATE`; `UNIQUE(stream_id, sequence)` plus a linkage trigger as backstops |
| Keys | One active Ed25519 key per project; private keys never stored in event rows; pluggable `keys.Provider` (local AES-256-GCM-wrapped keys, file-backed keys; KMS/HSM/remote signer later) |
| Rotation | New key becomes active, old key is retired but kept (public part forever) so history stays verifiable |
| Checkpoints | Signed statements `(stream, sequence, headHash, createdAt)` every N events / T time, exportable and externally anchorable |
| Verification | One Go package (`pkg/verify`) used by the API server, the CLI and the offline evidence verifier |
| Evidence export | ZIP with signed manifest, integrity skeleton (`chain.jsonl`), disclosed events, checkpoints, public keys; verifiable offline |
| Tenancy | Tenant → Project → Stream → Event; every query is scoped by tenant/project derived from the authenticated principal |
| API auth | Project-scoped API keys (`dlk_…`), SHA-256 hashed at rest, shown once |
| Dashboard auth | Email + password (Argon2id) → opaque session token (`dls_…`) held only in an HTTP-only cookie by the Next.js server |
| License | Apache-2.0 |

---

## 2. Components

```
                   ┌──────────────────────────┐
  application ───► │  REST API  (delil-server)│ ◄── dashboard (Next.js, BFF)
  TS SDK / curl    │  auth · validation ·     │ ◄── CLI (delil)
                   │  redaction · diff        │
                   └────────────┬─────────────┘
                                │ append (one tx per request)
                   ┌────────────▼─────────────┐
                   │ audit.Appender           │──► keys.Signer (local / file / KMS…)
                   │  canonicalize → hash →   │
                   │  link → sign → insert    │
                   └────────────┬─────────────┘
                                │
                   ┌────────────▼─────────────┐
                   │ PostgreSQL               │  append-only triggers, linkage trigger,
                   │ audit_events, streams,   │  least-privilege runtime role
                   │ checkpoints, keys, …     │
                   └────────────┬─────────────┘
                                │ records
                   ┌────────────▼─────────────┐
                   │ pkg/verify (pure Go)     │ ◄── also fed by the CLI over HTTP,
                   │ recompute everything     │     and by evidence packages offline
                   └──────────────────────────┘
```

Packages that third parties may want to audit or reuse live under `pkg/` and have no
database or network dependencies:

* `pkg/jcs` — RFC 8785 canonicalizer with strict input validation
* `pkg/integrity` — record/header/checkpoint types, hashing, signing messages, key IDs
* `pkg/verify` — the verification engine
* `pkg/evidence` — evidence package writer and offline reader/verifier

Server-only code lives under `internal/` (storage, API, auth, key providers, jobs).

---

## 3. Event model

An application submits:

```json
{
  "stream": "contracts",
  "actor": { "type": "user", "id": "user_128", "displayName": "Sarkhan Mahabbatli" },
  "action": "contract.approved",
  "resource": { "type": "contract", "id": "contract_813" },
  "before": { "status": "pending" },
  "after":  { "status": "approved" },
  "data": { },
  "metadata": { "requestId": "req_123" },
  "context": { "requestId": "req_123", "sourceIp": "203.0.113.7", "userAgent": "…" },
  "occurredAt": "2026-10-02T09:15:00Z"
}
```

The server validates the request (strict schema, unknown fields rejected), applies the
project's redaction rules, computes a structured diff when both `before` and `after`
keys are present, and produces the **event content** — the exact object that is
canonicalized and hashed:

```json
{
  "action": "contract.approved",
  "actor": { "displayName": "Sarkhan Mahabbatli", "id": "user_128", "type": "user" },
  "after": { "status": "approved" },
  "before": { "status": "pending" },
  "changes": [ { "from": "pending", "op": "replace", "path": "/status", "to": "approved" } ],
  "context": { "requestId": "req_123", "sourceIp": "203.0.113.7", "userAgent": "…" },
  "metadata": { "requestId": "req_123" },
  "occurredAt": "2026-10-02T09:15:00.000000Z",
  "redactions": [ "/after/password" ],
  "resource": { "id": "contract_813", "type": "contract" }
}
```

Rules:

* Absent optional members are **omitted**, never serialized as `null`. An explicit
  `null` for `before`/`after` is meaningful (resource did not exist / no longer exists)
  and is preserved.
* `changes` uses RFC 6901 JSON Pointer paths, ops `add` / `remove` / `replace`, sorted
  by path. Arrays are compared as whole values (documented limitation; avoids
  ambiguous LCS diffs).
* Projects may choose `retainStates: "diff"` to drop `before`/`after` after the diff is
  computed (data minimisation).
* `occurredAt` is **client-asserted**; `recordedAt` (in the header) is assigned by the
  server. Timestamps are normalised to UTC with exactly six fractional digits
  (`2006-01-02T15:04:05.000000Z`) because PostgreSQL `timestamptz` has microsecond
  precision and the value must round-trip byte-for-byte.

---

## 4. Canonicalization

RFC 8785 (JCS) is used for every hashed JSON object (event content, event header,
checkpoint body, export manifest). DƏLİL implements JCS itself in `pkg/jcs` (≈300
lines, fully tested) so that the canonical form is under our control and auditable.

Input profile (stricter than plain JSON; violations are rejected, never "repaired"):

* UTF-8 only; invalid UTF-8 → error (Go's `encoding/json` silently substitutes U+FFFD,
  which would alter data before hashing — we do not use it for hashed input).
* No duplicate object member names (I-JSON, RFC 7493 §2.3).
* No unpaired UTF-16 surrogates in `\u` escapes.
* No U+0000 in strings (cannot be stored in PostgreSQL text/jsonb reliably).
* Numbers are IEEE-754 binary64. Integer literals with magnitude > 2^53 are rejected
  (they cannot be represented exactly; clients must send them as strings). Literals
  that overflow to ±Inf are rejected.
* Maximum nesting depth 32.

Output: members sorted by UTF-16 code units of their names, minimal string escaping as
specified by RFC 8785 §3.2.2.2, numbers serialised with the ECMAScript
`Number.prototype.toString` algorithm (§3.2.2.3), no insignificant whitespace.

Conformance is tested against the RFC 8785 examples, against a corpus of numbers
serialised by V8 (`JSON.stringify`) and with fuzzing (`canonicalize(canonicalize(x)) ==
canonicalize(x)`).

---

## 5. Cryptographic construction (schema version 1)

Notation: `H(x) = SHA-256(x)`, `‖` concatenation, `0x00` a single zero byte, tags are
ASCII. Hashes are rendered as lowercase hex; signatures and public keys as standard
base64.

```
payloadHash   = H( "delil:v1:payload"           ‖ 0x00 ‖ JCS(content) )
eventHash     = H( "delil:v1:event"             ‖ 0x00 ‖ JCS(header)  )
signature     = Ed25519.Sign( sk, "delil:v1:event-signature" ‖ 0x00 ‖ eventHash )   (32 raw bytes)

checkpointHash = H( "delil:v1:checkpoint"       ‖ 0x00 ‖ JCS(checkpointBody) )
checkpointSig  = Ed25519.Sign( sk, "delil:v1:checkpoint-signature" ‖ 0x00 ‖ checkpointHash )

manifestHash  = H( "delil:v1:manifest"          ‖ 0x00 ‖ JCS(manifest) )
manifestSig   = Ed25519.Sign( sk, "delil:v1:manifest-signature" ‖ 0x00 ‖ manifestHash )

fingerprint   = hex( H(rawPublicKey32) )
keyId         = "ed25519:" ‖ first 32 hex chars of fingerprint
```

The **event header** (all members required):

```json
{
  "eventId": "evt_01J…",
  "keyId": "ed25519:…",
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

Why this shape:

* **Domain separation** makes it impossible to reinterpret a payload hash as an event
  hash, or a checkpoint signature as an event signature, even though the same key
  signs both. The tag is followed by `0x00`, which never appears inside a tag and
  never appears raw in JCS output, so the encoding is unambiguous.
* **Two-level hashing** (content → payloadHash → header → eventHash) means the chain
  can be verified from headers alone. That enables selective-disclosure evidence
  packages (prove an event exists in an intact chain without revealing neighbouring
  events) and leaves room for future content erasure with tombstones.
* The header binds tenant, project and stream, so an event cannot be transplanted to
  another stream or tenant without breaking its hash.
* `keyId` is inside the hashed header, binding the event to its signing key.
* `previousHash` for sequence 1 is 32 zero bytes (the genesis value). Sequence numbers
  start at 1 and are contiguous.
* Ed25519 is deterministic (no per-signature randomness to get wrong), fast to verify,
  and supported by Go's standard library, Node's `crypto`, and the major cloud KMSs.
  We sign the 32-byte hash with **pure** Ed25519 (not Ed25519ctx/ph) for KMS/HSM
  compatibility; domain separation is done in the message instead.
* The suite is fixed by `schemaVersion`. A future suite (e.g. SHA-384 + another
  algorithm, or a post-quantum signature) is a new schema version; old events keep
  verifying under v1 rules.

No novel cryptography is introduced: only SHA-256, Ed25519, AES-256-GCM (key
wrapping), HKDF-SHA256 (key derivation) and Argon2id (passwords), all from Go's
standard library or `golang.org/x/crypto`.

Known-answer test vectors (fixed key seed, fixed content → expected hashes and
signature) are published in `docs/test-vectors.json` so that independent verifiers can
be written in other languages.

---

## 6. Storage model

Hierarchy: `tenants → projects → audit_streams → audit_events`.

`audit_events` stores the immutable header fields as columns, the canonical content as
`text` (the exact bytes that were hashed), and a few **denormalised index columns**
(`actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`, `occurred_at`) for
filtering. The API always renders events from the canonical content, never from the
index columns, and verification checks that the index columns still match the signed
content (`indexed_field_mismatch`), so tampering with them is detected too.

Hashes are `bytea` with `CHECK (octet_length(...) = 32)`; signatures `bytea` (64).

`audit_streams` holds the chain head: `head_sequence`, `head_hash`,
`head_recorded_at`. It is updated in the same transaction as the insert.

### 6.1 Append protocol and concurrency

```
BEGIN;                                             -- READ COMMITTED
INSERT INTO audit_streams … ON CONFLICT (project_id, name) DO NOTHING;   -- auto-create
SELECT id, head_sequence, head_hash, head_recorded_at
  FROM audit_streams WHERE project_id = $1 AND name = $2 FOR UPDATE;      -- per-stream lock
SELECT … FROM signing_keys WHERE project_id = $1 AND status = 'active' FOR KEY SHARE;
-- for each event, in request order:
--   sequence     = head_sequence + 1
--   previousHash = head_hash
--   recordedAt   = max(now_µs, head_recorded_at)   -- non-decreasing per stream
--   content → payloadHash → header → eventHash → signature (+ self-verify)
INSERT INTO audit_events …;
UPDATE audit_streams SET head_sequence = …, head_hash = …, head_recorded_at = …;
INSERT INTO idempotency_keys … ;                  -- when an Idempotency-Key was sent
COMMIT;
```

* The row lock serialises writers **per stream**; different streams append in
  parallel. Batches touching several streams lock them in sorted order (no deadlocks).
* The signing key row is share-locked so a concurrent rotation waits for in-flight
  appends and no event is signed by a key after it was retired.
* Backstops in the database, independent of application code:
  * `UNIQUE (stream_id, sequence)`, `CHECK (sequence > 0)`.
  * A `BEFORE INSERT` trigger rejects any event whose `previous_hash` is not the
    `event_hash` of `sequence - 1` in the same stream (or the zero hash for sequence 1),
    and whose `recorded_at` is earlier than its predecessor's.
  * A `BEFORE UPDATE` trigger on `audit_streams` forbids moving the head backwards or
    pointing it at a hash that is not the event at that sequence.
* Any failure (validation, signer error, constraint) rolls back the whole request —
  batches are all-or-nothing.
* Concurrency is covered by tests that append from many goroutines to one stream and
  to many streams, then verify contiguity and linkage.

Signing happens while the stream lock is held. With local keys this costs tens of
microseconds; with a remote KMS it bounds per-stream throughput to roughly
1 / signing latency. This is documented; batching and spreading load over streams are
the mitigations.

### 6.2 Immutability (defence in depth, honestly scoped)

1. The API has no update/delete operations for events or checkpoints.
2. Triggers reject `UPDATE`, `DELETE` and `TRUNCATE` on `audit_events` and
   `checkpoints`. They stop accidents and application-level bugs, **not** a superuser
   or table owner, who can disable triggers.
3. A least-privilege runtime role (`delil_app`) is granted only `SELECT, INSERT` on
   `audit_events`/`checkpoints`. Migrations run as a separate owner role. The default
   docker-compose setup uses this split.
4. Cryptographic verification is the control that actually **detects** tampering by
   anyone, including superusers. Steps 1–3 only reduce the chance of it happening.

---

## 7. Signing strategy and key management

* One **active** Ed25519 key per project; any number of retired/revoked keys.
* `signing_keys` stores the public key, fingerprint-derived `keyId`, status and
  validity timestamps. Private material never touches `audit_events`.
* `keys.Provider` interface:
  * `local` (default): the 32-byte Ed25519 seed is wrapped with AES-256-GCM under a
    key derived via HKDF-SHA256 from `DELIL_MASTER_KEY`, with AAD binding the
    ciphertext to its `keyId` and project. A database dump alone does not reveal
    signing keys.
  * `file`: PKCS#8 PEM files in `DELIL_KEY_DIR` (0600), for operators who mount
    secrets as files.
  * `kms` / `hsm` / remote signer: same interface (`Generate`, `Signer(record)`),
    documented as roadmap; nothing in the data model assumes local key material.
* **Rotation**: in one transaction, lock the active key `FOR UPDATE` (waits for
  in-flight appends), insert the new key as `active`, mark the old key `retired` with
  `retired_at`. Old public keys remain forever, so historical signatures still verify.
* **Revocation** (suspected compromise): mark `revoked` with a timestamp. Verification
  reports events signed by a revoked key with `recordedAt` after the revocation time as
  failures. Events signed before revocation still verify, but operators must treat
  the whole period of possible compromise as suspect — see the threat model.
* In development only, if no master key is configured, one is generated and persisted
  in the data directory with a loud warning. In production the server refuses to start
  without an explicit key.

---

## 8. Checkpoints and witnessing

A checkpoint is a signed statement about a stream head:

```json
{ "checkpointId": "chk_…", "createdAt": "…", "headHash": "…", "keyId": "…",
  "projectId": "prj_…", "schemaVersion": 1, "sequence": 1000,
  "stream": "contracts", "tenantId": "org_…" }
```

* Created by a background worker when a stream has ≥ N new events (default 1000) or
  new events older than T (default 1 h), and on demand through the API.
* Stored append-only. An `Anchor` interface allows publishing checkpoints elsewhere
  (filesystem/WORM directory in v0.1; RFC 3161 TSA, object storage with retention
  lock, transparency logs as roadmap). Blockchain anchoring is not a dependency.
* **Witnessing**: anyone can save a checkpoint (`delil checkpoints save`) and later run
  `delil verify --witness cp.json`. If the stream no longer contains that exact head at
  that sequence, the history was rolled back or forked. This is the concrete
  mitigation for whole-database rollback, which no in-database mechanism can detect.

---

## 9. Verification procedure

`pkg/verify` consumes records in sequence order (streamed in batches, constant memory)
and independently recomputes everything. Per record (in parallel within a batch):

1. `schemaVersion` supported; `tenantId/projectId/stream` equal the stream being
   verified.
2. Content present → canonicalize with `pkg/jcs`; must already be canonical when read
   from the database (`payload_not_canonical`); `H(payload)` must equal `payloadHash`
   (`payload_hash_mismatch`).
3. Index columns (database mode) match the content (`indexed_field_mismatch`).
4. Recompute the header hash → must equal `eventHash` (`event_hash_mismatch`).
5. Key lookup in the **trusted** key set (`unknown_signing_key`); validity window
   (`signing_key_revoked`, warnings for use outside the active window).
6. Ed25519 verification of the signature (`signature_invalid`).

Sequentially:

7. `sequence` = previous + 1 (`sequence_gap`, `sequence_out_of_order`).
8. `previousHash` = stored `eventHash` of the previous record, or the anchor (zero hash
   at genesis, a checkpoint's head hash for partial chains) (`previous_hash_mismatch`,
   `anchor_mismatch`).
9. `recordedAt` non-decreasing (`timestamp_regression`).

After the scan:

10. The stream head pointer matches the last record (`head_mismatch`).
11. Every checkpoint (and witness) has a valid signature and matches the event hash at
    its sequence (`checkpoint_mismatch`); a checkpoint beyond the last record reveals
    truncation or rollback (`checkpoint_beyond_head`).

Comparing linkage against the previous record's **stored** hash pinpoints where the
chain was cut; per-record checks pinpoint which record was altered. The report gives
the first failing sequence, every failure (capped, with a total count), expected vs
found values, and states that events after the first failure cannot be trusted through
the current chain. Machine-readable JSON and human output come from the same report.

Where verification runs matters: verification **by the server** is a convenience;
verification **by the CLI** (which downloads raw records and uses its own copy of
`pkg/verify`, optionally with pinned public keys) and **offline** verification of
evidence packages do not trust the server at all.

---

## 10. Evidence packages

ZIP containing:

| File | Content |
|---|---|
| `manifest.json` | format version, generator, tenant/project/stream, selection criteria, covered chain segment and anchor, SHA-256 and size of every other file |
| `signature.json` | Ed25519 signature over `manifestHash` with the signing `keyId` |
| `chain.jsonl` | integrity skeleton: every header in the covered segment, from the anchor (genesis or a checkpoint) to the last selected event |
| `events.jsonl` | disclosed events: header + exact canonical content |
| `checkpoints.json` | signed checkpoints used as anchor or lying inside the segment |
| `public-keys.json` | every key needed, with fingerprints and validity windows |
| `verification.json` | the server's verification of the segment at export time (informational) |
| `README.txt` | what the package proves, what it does not, how to verify it |

The offline verifier (`delil verify-export`) never extracts to disk, rejects duplicate
or unexpected entry names, absolute paths, `..`, symlinks and oversized/high-ratio
entries, checks every file digest against the manifest, verifies the manifest
signature, the checkpoints, the full skeleton chain and the disclosed contents. Keys
can be pinned with `--trusted-keys`; otherwise the report states that the keys came
from the package itself and must be compared with an independently obtained copy.

---

## 11. Multi-tenancy and authorization

* Principals: **API key** (bound to one project, explicit scopes) or **dashboard user
  session** (bound to one tenant, role → scopes; project chosen per request with the
  `Delil-Project` header and checked to belong to the tenant).
* Scopes: `events:write`, `events:read`, `verify`, `exports`, `keys:read`,
  `keys:rotate`, `api_keys:manage`. Roles: `admin` (all but `events:write`), `auditor`
  (read, verify, exports, keys:read), `viewer` (read, keys:read).
* Every repository method takes the tenant and project IDs from the principal; lookups
  by ID always include them in the `WHERE` clause. Cross-tenant access returns 404
  (no existence oracle). Tenant isolation has dedicated tests.
* API keys: `dlk_<16 char id>_<52 char secret>` (32 random bytes), only the SHA-256 of
  the full key is stored, comparison is constant-time, raw key returned once. API keys
  are high-entropy, so a slow password hash is unnecessary.
* Sessions: 32 random bytes, stored hashed, absolute expiry, revocable. The browser
  holds the token only in an HTTP-only, SameSite=Lax cookie on the dashboard origin;
  the Go API never sets cookies, so it is not exposed to CSRF. Dashboard mutations go
  through Next.js Server Actions (Origin-checked).

---

## 12. Threat-model assumptions (summary)

Full analysis: `docs/threat-model.md`.

| Adversary | Can they tamper undetected? |
|---|---|
| Application client with an API key | No — can only append; cannot alter or remove past events. |
| Network attacker | No — TLS in deployment; signatures make records self-authenticating. |
| DBA / attacker with DB write access, **no signing key** | No — any change, deletion, insertion or reordering breaks hashes, links or signatures. **Truncating the tail** together with the head pointer and checkpoints is only detectable with an external witness or anchor. **Full rollback** of the database to an earlier consistent state is likewise only detectable with external witnesses. |
| Attacker with DB access **and** the signing key (or the master key + DB) | Yes, for the period the key is compromised: they can rewrite history and re-sign it. Detectable only with checkpoints held outside their reach (witnesses, anchors, exported packages). Key custody (KMS/HSM) is the mitigation. |
| Compromised API server (live) | Can sign arbitrary new events and refuse/alter incoming ones; cannot alter already-witnessed history without detection. |
| Clock manipulation | `recordedAt` is the server's clock, forced non-decreasing per stream; it is **not** a trusted timestamp. Trusted time requires anchoring checkpoints with an RFC 3161 TSA (roadmap). |

DƏLİL provides **tamper evidence**, not tamper prevention, and not legal
admissibility. Admissibility depends on jurisdiction and procedure.

---

## 13. Explicitly out of scope for v0.1 (roadmap)

KMS/HSM providers, RFC 3161/transparency-log anchoring, content erasure with
tombstones (the two-level hash already supports it), crypto-shredding, SSO/OIDC for
the dashboard, Go/Python/Java/.NET SDKs, multi-stream evidence packages, PDF reports,
horizontal sharding.
