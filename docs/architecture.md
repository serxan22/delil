# Architecture

DƏLİL is a small number of components around one PostgreSQL database. The
cryptographic core is a set of pure Go packages that the server, the CLI and the
offline verifier share. This document describes the implemented system; the
original design decisions are recorded in
[initial-architecture.md](initial-architecture.md).

## Components

```
                    ┌──────────────────────────────┐
 application ─────► │ delil-server                 │ ◄──── dashboard (Next.js; server-side
 (TS SDK, curl,     │  REST API · auth · limits    │       calls with the user's session)
  any HTTP client)  │  ingestion · exports         │ ◄──── delil CLI (reads the raw chain,
                    │  workers: checkpoints,       │       verifies locally)
                    │  scheduled verification,     │
                    │  export builder, cleanup     │ ────► /metrics (Prometheus)
                    └──────────────┬───────────────┘ ────► anchor directory (checkpoints)
                                   │ SQL as delil_app (SELECT/INSERT on audit tables)
                    ┌──────────────▼───────────────┐
                    │ PostgreSQL 16+               │
                    │ append-only triggers         │
                    └──────────────────────────────┘

 evidence package (ZIP) ──► delil verify-export   (offline: no server, no database)
```

| Component | Path | Role |
|---|---|---|
| `delil-server` | `cmd/delil-server`, `internal/` | API, ingestion, verification, exports, background workers, operator commands (`migrate`, `bootstrap`, `keys rotate`, `verify`, …) |
| `delil` CLI | `cmd/delil`, `internal/cli` | Independent verification, inspection, exports, key pinning, witnesses. Exit codes for CI |
| `delil-bench` | `cmd/delil-bench` | Engine and HTTP load benchmarks ([benchmarks](benchmarks.md)) |
| Cryptographic core | `pkg/jcs`, `pkg/integrity`, `pkg/verify`, `pkg/evidence` | Canonicalization, formats, hashing, signing messages, verification, evidence packages. No I/O |
| Go client | `pkg/client` | HTTP client used by the CLI and the benchmark, including `VerifyStreamLocal` |
| TypeScript SDK | `sdk/typescript` | Typed client with safe retries and idempotency; zero runtime dependencies |
| Dashboard | `apps/dashboard` | Next.js 16 / React 19 back-office for auditors and administrators |

## Data model

```
tenants ──< projects ──< audit_streams ──< audit_events
   │            │              └──< checkpoints ──< checkpoint_anchors
   │            ├──< signing_keys
   │            ├──< api_keys
   │            ├──< verification_runs, stream_verifications
   │            ├──< exports
   │            └──< idempotency_keys
   └──< users ──< sessions
```

Fourteen tables in [`migrations/0001_initial_schema.sql`](../migrations/0001_initial_schema.sql).
The important ones:

- **`audit_events`**: the immutable header fields as columns, the canonical
  content as `text` (the exact bytes that were hashed), `event_hash`,
  `signature`, and denormalized index columns (`actor_type`, `actor_id`,
  `action`, `resource_type`, `resource_id`, `occurred_at`) for filtering. The API
  always renders events from the canonical content. Verification checks that
  the index columns still match it.
- **`audit_streams`**: one row per stream with its head (`head_sequence`,
  `head_hash`, `head_recorded_at`), updated in the same transaction as each
  append.
- **`signing_keys`**: public key, key id, status (`active`, `retired`,
  `revoked`), validity timestamps, and the provider's wrapped private material.
  At most one active key per project (a partial unique index).
- **`checkpoints`** and **`checkpoint_anchors`**: signed stream heads and where
  they were published.
- **`verification_runs`** and **`stream_verifications`**: verification history
  and the latest result per stream, which gives events their
  `verified`/`failed`/`unverified` status in the API and dashboard.

Hashes are `bytea` with `CHECK (octet_length(…) = 32)`. Sequences are
`UNIQUE (stream_id, sequence)` and positive.

## Ingestion

`POST /v1/events` and `POST /v1/events/batch` go through these steps:

1. **Middleware**: request id (`X-Request-Id`, also echoed in errors), client IP
   (`DELIL_TRUSTED_PROXIES` decides whether `X-Forwarded-For` is believed),
   security headers, CORS for listed origins only, body-size limit, panic
   recovery, and Prometheus metrics by route pattern.
2. **Authentication and authorization**: API key or session, then scope check
   (`events:write`), then the per-principal rate limiter.
3. **Strict parsing** with the JCS input profile (invalid UTF-8, duplicate keys,
   unsafe numbers and excessive depth are rejected) and schema validation
   (unknown members rejected, identifiers and lengths checked). Every invalid
   field is reported in `details.errors`.
4. **Preparation** (`internal/audit.Prepare`):
   - copy `before`/`after`, then compute the structured diff (`changes`, RFC 6901
     paths, ops `add`/`remove`/`replace`, sorted; arrays compared as whole
     values);
   - **redact** `before`, `after`, `data`, `metadata` and the diff with the
     project's rules (default denylist plus configured keys and JSON Pointers;
     modes `redact`, `remove`, `mask`), and record the redacted paths in
     `redactions`;
   - drop `before`/`after` when the project uses `retainStates: "diff"`;
   - canonicalize and enforce the per-event size limit.
5. **Append** (below), then **respond** with the receipt: id, sequence, hashes,
   signature and key id.

With an `Idempotency-Key`, the request body's hash and the resulting event ids
are stored in the same transaction. A retry with the same key and body returns
the original receipts (`Idempotent-Replayed: true`). The same key with a
different body is rejected. Two concurrent requests with the same key resolve to
one commit: the loser's transaction rolls back and it answers as a retry would.

## Append protocol

```
BEGIN (READ COMMITTED)
  create missing streams (ON CONFLICT DO NOTHING), checking the per-project stream limit
  SELECT … FROM audit_streams … FOR UPDATE           -- in sorted order: no deadlocks
  SELECT the active signing key … FOR KEY SHARE      -- rotation (FOR UPDATE) waits for in-flight appends
  for each event in request order:
      sequence = head + 1; previousHash = head hash; recordedAt = max(now, head time)
      seal: payloadHash → header → eventHash → Ed25519 signature → verify it
  INSERT events; UPDATE stream heads                 -- one pipelined batch
  INSERT idempotency record                          -- if a key was sent
COMMIT
```

- The row lock serializes writers **per stream**. Different streams append in
  parallel. A batch that touches several streams locks them in name order.
- Signing happens while the lock is held. With local keys this takes
  microseconds; a remote signer would cap a single stream's throughput at about
  1 / signing latency. Spreading load over streams and batching are the levers.
- Database backstops, independent of the application: the linkage trigger
  rejects an event whose `previous_hash` is not its predecessor's `event_hash`
  (or zeros at sequence 1) and whose `recorded_at` goes backwards; the head
  trigger forbids moving a head backwards or to a hash that is not the event at
  that sequence; append-only triggers reject `UPDATE`, `DELETE` and `TRUNCATE`.
- Any error rolls back the whole request.

Concurrency tests append from many goroutines to one stream and to many
streams, then check contiguity and linkage, and race idempotent requests and key
rotations against appends.

## Verification paths

| Path | Source of records | Keys |
|---|---|---|
| `POST /v1/streams/{name}/verify`, `POST /v1/verify`, scheduled runs | database, read in pages of 2,000 | from the database |
| `delil verify` | `GET /v1/streams/{name}/chain`, verified on the client | server-provided, or pinned with `--trusted-keys` |
| `delil-server verify` | database, for operators | from the database |
| `delil verify-export` | an evidence package | from the package, or pinned |

All of them call `pkg/verify`. Scheduled verification (`DELIL_VERIFY_INTERVAL`,
default 6 h) records a run per project, increments
`delil_verification_failures_total` and logs `INTEGRITY VERIFICATION FAILED` on
any failure. Alert on both.

## Background workers

Every worker takes a PostgreSQL advisory lock before it runs, so several server
instances can run side by side and each job runs on one instance at a time.

| Worker | Interval | Does |
|---|---|---|
| Checkpoints | `DELIL_CHECKPOINT_POLL` (30 s) | signs the head of streams with ≥ `DELIL_CHECKPOINT_EVERY` new events or new events older than `DELIL_CHECKPOINT_MAX_AGE`, and publishes them to the anchor directory |
| Scheduled verification | `DELIL_VERIFY_INTERVAL` (6 h) | verifies every project and records the runs |
| Export builder | 5 s | builds queued evidence packages into `DELIL_EXPORT_DIR` after verifying the stream, and records each file's SHA-256 |
| Cleanup | 10 min | removes expired sessions, idempotency keys and expired export files |

## Authentication and tenancy

- **API keys** (`dlk_<id>_<secret>`) belong to one project and carry explicit
  scopes: `events:write`, `events:read`, `verify`, `exports`, `keys:read`,
  `keys:rotate`, `api_keys:manage`. Only the SHA-256 of the key is stored, and
  comparison is constant-time. A key can only create keys with scopes it holds.
- **Dashboard sessions** (`dls_…`) come from email and password (Argon2id, login
  rate-limited per IP and per email with identical errors for unknown accounts).
  A user belongs to one tenant; their role maps to scopes. `admin` has
  everything except `events:write`, plus `project:manage` and `tenant:manage`.
  `auditor` can read, verify, export and read keys. `viewer` can read events and
  keys. Sessions name the project per request (`Delil-Project`), and the project
  is checked to belong to the user's tenant.
- **Isolation**: every store method takes the tenant and project from the
  principal and includes them in the `WHERE` clause. Objects of other tenants
  return 404, so their existence is not revealed.
- **Dashboard** (BFF): the browser holds only an HTTP-only, `SameSite=Lax`
  cookie on the dashboard's origin. Next.js calls the API server-side, and
  mutations are Server Actions (Origin-checked). The Go API never sets cookies,
  so it has no CSRF surface.

## Exports

`POST /v1/exports` stores the request and returns `202`. The export worker
resolves the sequence range (from sequences or a time range), chooses the anchor
(the latest checkpoint at or before the start, otherwise genesis), writes the
skeleton for the whole segment and the content of events matching the
disclosure filters, and signs the manifest with the project's active key. The
stream is verified on the server first; the result goes into
`verification.json` and the export's `verificationValid`. The package's
SHA-256 is recorded and returned with the export. `delil export` verifies the
downloaded file with `pkg/evidence` unless `--no-verify` is given. Packages expire
after `DELIL_EXPORT_TTL` (7 days). The format is described in the
[cryptographic model](cryptographic-model.md#7-evidence-packages).

## Observability

- Structured logs (`slog`, JSON or text) with request ids. Secrets, tokens and
  event content are never logged.
- `GET /health` (process up) and `GET /ready` (database reachable, migrations
  applied).
- Prometheus metrics (`/metrics`, or a separate listener with
  `DELIL_METRICS_ADDR`, optionally bearer-protected with `DELIL_METRICS_TOKEN`):
  `delil_events_ingested_total`, `delil_events_rejected_total{reason}`,
  `delil_event_ingest_duration_seconds`, `delil_verifications_total{scope,result}`,
  `delil_verification_failures_total{scope}`,
  `delil_api_requests_total{method,route,status}`,
  `delil_api_request_duration_seconds`, `delil_checkpoints_created_total`,
  `delil_exports_total{result}`, `delil_stream_head_sequence`, `delil_build_info`.

## Repository layout

See [CONTRIBUTING.md](../CONTRIBUTING.md#repository-layout).
