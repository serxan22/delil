# Deployment

DƏLİL runs as one stateless Go binary (`delil-server`) in front of
PostgreSQL 16 or newer, plus an optional Next.js dashboard. This guide covers
the local stack, a production setup, operations, and every configuration
variable.

## Local (Docker Compose)

```bash
cp .env.example .env
make dev            # docker compose up --build
make credentials    # admin login and API key, printed once on first start
```

| URL | Service |
|---|---|
| http://localhost:3000 | dashboard (log in with the bootstrap admin) |
| http://localhost:8080 | API (`/health`, `/ready`, `/openapi.yaml`, `/metrics`) |
| `127.0.0.1:5432` | PostgreSQL (owner `delil`, runtime role `delil_app`) |

The Compose file is a **development** configuration. Ports are bound to
`127.0.0.1`, cookies are not `Secure`, a master key is generated inside the
data volume, and the demo dataset is seeded. `make tamper-demo` edits a record
in this database and shows verification failing. `make reset` deletes all data.

## Production

### 1. Database roles

Use two roles: an **owner** that applies migrations and a **runtime** role
that cannot modify audit records.

```sql
CREATE ROLE delil LOGIN PASSWORD '…';                     -- owner (migrations only)
CREATE DATABASE delil OWNER delil;
CREATE ROLE delil_app LOGIN PASSWORD '…' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE delil TO delil_app;
```

`delil-server migrate` applies the schema as the owner and, with
`DELIL_DB_APP_ROLE=delil_app`, grants the runtime role exactly what it needs:
`SELECT, INSERT` on `audit_events`, `checkpoints` and `checkpoint_anchors`, and
**never** `UPDATE`, `DELETE` or `TRUNCATE` on them. CI checks that the runtime
role is denied both statements.

### 2. Master key

The `local` key provider encrypts signing keys with a 32-byte master key. In
production the server refuses to start without one.

```bash
openssl rand -base64 32      # store it in your secret manager
```

Provide it as `DELIL_MASTER_KEY` (from the secret manager's environment
injection) or `DELIL_MASTER_KEY_FILE` (a mounted secret file). Keep it apart
from database backups: a dump together with the master key lets someone sign
as the project. **Losing it makes new signing impossible** for the existing
keys. History stays verifiable, because verification only needs public keys,
but you will have to revoke the old keys and create new ones. Back it up
separately.

Alternatively, `DELIL_KEY_PROVIDER=file` reads PKCS#8 PEM keys from
`DELIL_KEY_DIR` (mode 0600). This suits secrets mounted by an orchestrator.

### 3. Migrate, bootstrap, serve

```bash
export DELIL_ENV=production
export DELIL_MIGRATION_DATABASE_URL='postgres://delil:…@db:5432/delil?sslmode=verify-full'
export DELIL_DATABASE_URL='postgres://delil_app:…@db:5432/delil?sslmode=verify-full'
export DELIL_DB_APP_ROLE=delil_app
export DELIL_MASTER_KEY_FILE=/run/secrets/delil-master-key
export DELIL_DATA_DIR=/var/lib/delil            # exports; must be shared by all instances
export DELIL_ANCHOR_DIR=/mnt/worm/delil-anchors # checkpoint witnesses on storage the DBAs cannot rewrite

delil-server migrate          # as the owner; idempotent; run before every upgrade
DELIL_BOOTSTRAP_ADMIN_EMAIL=you@example.com delil-server bootstrap   # once: prints the admin password and API key
delil-server serve
```

Or use the images from GitHub Container Registry
(`ghcr.io/serxan22/delil-server`, `ghcr.io/serxan22/delil-dashboard`). They
run as non-root, the server image is distroless, and both carry SLSA provenance
(`gh attestation verify oci://ghcr.io/serxan22/delil-server:<version> -R serxan22/delil`).

### 4. TLS and the dashboard

Put a TLS-terminating reverse proxy in front of both services. Set
`DELIL_TRUSTED_PROXIES` to the proxy's addresses so client IPs (used in rate
limits, logs and session records) come from `X-Forwarded-For`; otherwise the
header is ignored.

The dashboard needs `DELIL_API_URL` (the API's internal URL, reached
server-side only) and, behind HTTPS, `DELIL_COOKIE_SECURE` left at its default
(`true`). Browsers never talk to the API directly, so CORS can stay disabled.
Only set `DELIL_CORS_ALLOWED_ORIGINS` for your own browser-based clients, and
remember that API keys must never reach a browser.

### 5. Observability and alerts

- Scrape `/metrics`. In production, move it to an internal listener
  (`DELIL_METRICS_ADDR=:9090`) or protect it with `DELIL_METRICS_TOKEN`.
- **Alert on** any increase of `delil_verification_failures_total`, and on log
  lines `INTEGRITY VERIFICATION FAILED`. Treat them as security incidents (see
  [security](security.md#responding-to-a-verification-failure)).
- Also watch `delil_events_rejected_total` (client bugs or abuse),
  `/ready`, and the age of the last checkpoint per stream.

### 6. Scaling

- Several server instances can run against one database. Background jobs take
  PostgreSQL advisory locks, so each runs on one instance at a time.
  `DELIL_DATA_DIR` (exports) must be shared storage, because the instance that
  serves a download may not be the one that built it.
- Appends serialize per stream, not globally. Throughput grows with the number
  of streams written concurrently and with batching. See [benchmarks](benchmarks.md).
- Size the connection pool (`DELIL_DB_MAX_CONNS`, default 20 per instance)
  against PostgreSQL's `max_connections`.

### 7. Backups and restore

- Back up PostgreSQL with your usual tooling (`pg_dump`, base backups plus WAL).
  Back up the master key separately, and the anchor directory and saved
  witnesses on different storage.
- After restoring, run `delil-server verify` or `delil verify` before taking
  traffic. **A restore is a rollback.** Witnesses taken after the backup will
  report `checkpoint_beyond_head`, which is expected and correct. Record the
  restore as an incident, so the gap is explained rather than hidden.

### 8. Upgrades

1. Read the [changelog](../CHANGELOG.md).
2. Back up.
3. `delil-server migrate` with the new version (it applies pending migrations
   and re-grants runtime privileges).
4. Roll the servers. `serve` refuses to start against a schema that is not up
   to date unless `DELIL_AUTO_MIGRATE=true`, which is meant for development.

## Configuration reference

All configuration is read from environment variables at start. Invalid values
stop the server with a list of every problem.

### Server and database

| Variable | Default | Description |
|---|---|---|
| `DELIL_ENV` | `production` | `production` or `development` (development generates a master key and relaxes checks) |
| `DELIL_HTTP_ADDR` | `:8080` | listen address |
| `DELIL_DATABASE_URL` | required | runtime connection (the `delil_app` role) |
| `DELIL_MIGRATION_DATABASE_URL` | `DELIL_DATABASE_URL` | owner connection used by `migrate` |
| `DELIL_DB_APP_ROLE` | — | role that `migrate` grants runtime privileges to |
| `DELIL_AUTO_MIGRATE` | `false` | migrate on `serve` (development) |
| `DELIL_DB_MAX_CONNS` | `20` | connection pool size (max 1000) |
| `DELIL_SHUTDOWN_TIMEOUT` | `20s` | graceful shutdown limit |

### Keys and storage

| Variable | Default | Description |
|---|---|---|
| `DELIL_KEY_PROVIDER` | `local` | `local` (AES-256-GCM-wrapped keys in the database) or `file` |
| `DELIL_MASTER_KEY` | — | base64 of 32 bytes; required in production for `local` |
| `DELIL_MASTER_KEY_FILE` | — | file containing the base64 master key |
| `DELIL_KEY_DIR` | — | directory of PKCS#8 PEM keys for `file` |
| `DELIL_DATA_DIR` | `/var/lib/delil` | data directory (development master key, exports) |
| `DELIL_EXPORT_DIR` | `$DELIL_DATA_DIR/exports` | evidence packages |
| `DELIL_EXPORT_TTL` | `168h` | how long packages can be downloaded |
| `DELIL_ANCHOR_DIR` | — | write every checkpoint here (create-only); use WORM or separate storage |

### Integrity jobs

| Variable | Default | Description |
|---|---|---|
| `DELIL_CHECKPOINT_EVERY` | `1000` | checkpoint a stream after this many new events |
| `DELIL_CHECKPOINT_MAX_AGE` | `1h` | … or when its newest unchecked event is this old |
| `DELIL_CHECKPOINT_POLL` | `30s` | checkpoint worker interval |
| `DELIL_VERIFY_INTERVAL` | `6h` | scheduled verification of every project (`0` disables) |

### Limits

| Variable | Default | Description |
|---|---|---|
| `DELIL_MAX_EVENT_BYTES` | `262144` | canonical size of one event (1 KiB to 16 MiB; projects may lower it) |
| `DELIL_MAX_BATCH_EVENTS` | `500` | events per batch request (1 to 10,000) |
| `DELIL_MAX_REQUEST_BYTES` | `4194304` | request body limit (≥ the event limit) |
| `DELIL_MAX_STREAMS_PER_PROJECT` | `1000` | streams a project may create |
| `DELIL_IDEMPOTENCY_TTL` | `168h` | how long idempotency keys are remembered |
| `DELIL_RATE_LIMIT_RPS` | `100` | requests per second per API key or session |
| `DELIL_RATE_LIMIT_BURST` | `200` | burst size |
| `DELIL_LOGIN_RATE_LIMIT` | `10` | login attempts per IP and per email per 15 minutes |
| `DELIL_SESSION_TTL` | `12h` | dashboard session lifetime |

### HTTP, logs and metrics

| Variable | Default | Description |
|---|---|---|
| `DELIL_TRUSTED_PROXIES` | — | comma-separated addresses or CIDRs whose `X-Forwarded-For` is trusted |
| `DELIL_CORS_ALLOWED_ORIGINS` | — | comma-separated origins; `*` is rejected |
| `DELIL_METRICS_ADDR` | — | separate listener for `/metrics` (otherwise served on the main port) |
| `DELIL_METRICS_TOKEN` | — | require `Authorization: Bearer <token>` for metrics |
| `DELIL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DELIL_LOG_FORMAT` | `json` | `json` or `text` |

### First start

| Variable | Default | Description |
|---|---|---|
| `DELIL_BOOTSTRAP` | `false` | on `serve`, create the first organization, project, admin and API key if none exists |
| `DELIL_BOOTSTRAP_ORG_NAME` | `LegalFlow Demo` | organization name |
| `DELIL_BOOTSTRAP_PROJECT_NAME` | `LegalFlow` | project name |
| `DELIL_BOOTSTRAP_ADMIN_EMAIL` | `admin@delil.local` | administrator email |
| `DELIL_BOOTSTRAP_ADMIN_PASSWORD` | random | printed once if generated |
| `DELIL_DEMO_DATA` | `false` | seed a month of demo activity during bootstrap |

### Dashboard

| Variable | Default | Description |
|---|---|---|
| `DELIL_API_URL` | required | API base URL as reached from the dashboard server |
| `DELIL_COOKIE_SECURE` | `true` | set `false` only for plain-HTTP local development |
