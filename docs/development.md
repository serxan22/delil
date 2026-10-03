# Development

## Prerequisites

| Tool | Version | For |
|---|---|---|
| Go | 1.27.1 (from `go.mod`) | server, CLI, core packages |
| Node.js | 22.18+ (24 recommended) | SDK, dashboard, examples, test-vector checker |
| PostgreSQL | 16 or newer | database tests; Compose uses 18 |
| Docker + Compose | recent | `make dev`, end-to-end tests |
| golangci-lint | v2.14+, **built with Go 1.27** | `make lint` |

Release binaries of golangci-lint built with an older Go refuse to lint this
module. Build it with the project's toolchain:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
```

## Everyday commands

```bash
make help              # every target
make dev               # Compose stack: PostgreSQL, API (:8080), dashboard (:3000)
make credentials       # bootstrap admin password and API key
make test              # Go unit tests (-short), SDK and dashboard tests
make lint              # golangci-lint, SDK and dashboard type checks, ESLint
make fmt               # gofmt
make test-vectors      # Go and the independent Node.js verifier must agree
make openapi-lint      # Redocly
make benchmark         # micro-benchmarks and the engine benchmark
make examples          # build the SDK, run every example (needs DELIL_API_KEY)
make tamper-demo       # edit a record in the Compose database, watch verification fail
```

## Database tests

Most of the server is tested against real PostgreSQL: concurrency, triggers,
roles, idempotency races, tenant isolation, tamper scenarios. Point the tests at
any server where the role may create databases. Each test creates a fresh
database, migrates it and drops it afterwards.

```bash
docker run -d --name delil-test-pg -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:18-alpine
export DELIL_TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:55432/postgres?sslmode=disable'
make test-integration   # go test -race -count=1 ./...
```

Without `DELIL_TEST_DATABASE_URL`, database tests are skipped. CI always runs
them, against PostgreSQL 16 and 18.

## Running the server without Docker

```bash
createdb delil
export DELIL_ENV=development DELIL_AUTO_MIGRATE=true DELIL_BOOTSTRAP=true DELIL_DEMO_DATA=true
export DELIL_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/delil?sslmode=disable'
export DELIL_DATA_DIR=./.delil DELIL_LOG_FORMAT=text
go run ./cmd/delil-server serve          # prints the admin password and API key once

# dashboard, in another terminal
cd apps/dashboard && npm ci
DELIL_API_URL=http://localhost:8080 npm run dev
```

In development a master key is generated in `DELIL_DATA_DIR` on first start.

## End-to-end tests

`scripts/e2e.sh` runs against the Compose stack. CI runs it on every push.

```bash
cp .env.example .env && docker compose up -d --build --wait
scripts/e2e.sh          # leaves the database tampered at the end; make reset afterwards
```

It verifies the demo streams with pinned keys, checks that the runtime role
cannot `UPDATE` or `DELETE` audit records, runs the examples, the SDK
integration tests and a small load test, round-trips an evidence package, and
requires the tamper demo to be detected.

## Working on…

### The cryptographic core (`pkg/`)

- Read the [cryptographic model](cryptographic-model.md) first. Anything that
  changes canonical bytes, hashes or signatures needs a new schema version and
  a design discussion (see [CONTRIBUTING](../CONTRIBUTING.md#rules-for-changes)).
- `go test ./pkg/...` runs fast and needs no database. Add a scenario to
  `pkg/verify/verify_test.go` for every new failure mode.
- Regenerate test vectors only for an intentional construction change:
  `go test ./pkg/integrity -run TestKnownAnswerVectors -update`, then
  `node scripts/verify-test-vectors.mjs`.

### Migrations

Migrations are SQL files in `migrations/`, embedded into the binary and applied
in order by `delil-server migrate`. Never edit an applied migration. Add a new,
numbered file. Keep the runtime-role grants in `internal/db` in sync with new
tables, and add a guard test if a table holds audit data.

### The REST API

Update `api/openapi.yaml` with the handler. `TestOpenAPICoversRoutes` fails if
a route is missing from the document or the document lists a route that does
not exist. Run `make openapi-lint`. If the SDK exposes the endpoint, update
`sdk/typescript/src/types.ts` and its tests.

### The SDK

```bash
cd sdk/typescript
npm ci && npm test && npm run build
DELIL_TEST_URL=http://localhost:8080 DELIL_TEST_API_KEY=dlk_… npm run test:integration
```

### The dashboard

`apps/dashboard` is a Next.js App Router app that calls the API server-side
only (`src/lib/api.ts`). Session tokens live in an HTTP-only cookie, and
mutations are Server Actions in `src/app/actions.ts`.
`npm run lint && npm run typecheck && npm test && npm run build`.

## Releasing

1. Move the `Unreleased` entries in `CHANGELOG.md` under the new version and
   date. Bump `VERSION` in the `Makefile` and the SDK's `package.json`.
2. Tag: `git tag -s v0.2.0 -m v0.2.0 && git push origin v0.2.0`.
3. The release workflow builds binaries for six platforms with `SHA256SUMS` and
   provenance, publishes the GitHub release, and pushes multi-arch images to
   `ghcr.io/serxan22/delil-server` and `delil-dashboard`.
