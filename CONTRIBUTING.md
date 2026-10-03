# Contributing to DƏLİL

Thank you for helping. DƏLİL is security infrastructure, so the bar for
correctness is high, but the process is simple: open an issue to discuss
anything non-trivial, then send a focused pull request with tests.

Security vulnerabilities go through [private reporting](SECURITY.md), never a
public issue. Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Go 1.27, Node.js 22.18+ (24 recommended), PostgreSQL 16+ and Docker
with Compose. Details are in [docs/development.md](docs/development.md).

```bash
make dev            # PostgreSQL + API + dashboard via Docker Compose
make credentials    # the bootstrap admin login and API key

make test           # Go unit tests, SDK and dashboard tests
DELIL_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable \
  make test-integration   # every Go test against a real database, with -race
make lint           # golangci-lint, TypeScript type checks, ESLint
make test-vectors   # Go and an independent Node.js implementation must agree
```

`make help` lists every task. CI runs all of the above plus an end-to-end
suite on the Compose stack (`scripts/e2e.sh`) and the security scans described
in [SECURITY.md](SECURITY.md).

## Repository layout

| Path | Contents |
|---|---|
| `pkg/jcs`, `pkg/integrity`, `pkg/verify`, `pkg/evidence` | The cryptographic core. Pure Go, no database or network; meant to be audited and reused |
| `pkg/client` | Go API client used by the CLI |
| `internal/` | Server: storage, ingestion (`audit`), API, auth, keys, exports, workers |
| `cmd/delil-server`, `cmd/delil`, `cmd/delil-bench` | Server, CLI and benchmark binaries |
| `migrations/` | PostgreSQL schema (embedded, applied by `delil-server migrate`) |
| `api/openapi.yaml` | The REST API contract. A test fails if it drifts from the router |
| `sdk/typescript`, `apps/dashboard`, `examples/` | SDK, Next.js dashboard, runnable examples |
| `docs/` | Architecture, cryptographic model, threat model, operations |

## Rules for changes

- **Tests are required.** Bug fixes come with a test that fails without the fix.
  Database behaviour is tested against real PostgreSQL (`internal/testdb`), not mocks.
- **Never weaken verification.** `pkg/verify` must keep failing on every scenario
  in `internal/verification/tamper_test.go` and `pkg/verify/verify_test.go`. Add a
  scenario when you find a new way to tamper.
- **The integrity construction is versioned.** Changes to what is canonicalized,
  hashed or signed, or to the evidence package format, need a design discussion
  first, a new `schemaVersion`, regenerated `docs/test-vectors.json` that the
  Node.js checker (`scripts/verify-test-vectors.mjs`) still reproduces, and
  continued verification of existing chains.
- **Audit records are append-only.** No code path may UPDATE or DELETE
  `audit_events`. The runtime database role cannot, and tests assert it.
- **Keep the API documented.** Update `api/openapi.yaml` with every route or
  response change, and the SDK types if clients see it.
- **No secrets or real personal data** in code, fixtures, logs or screenshots.
- Keep dependencies minimal. New runtime dependencies need a reason in the PR.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) as the history
  does: `feat:`, `fix:`, `docs:`, `test:`, `build:`, `ci:`, `chore:`, with an
  optional scope (`fix(sdk): …`).
- One logical change per pull request. Explain *why* in the description and fill
  in the template's integrity-impact section.
- Add a line to `CHANGELOG.md` under **Unreleased** for user-visible changes.
- Contributions are licensed under the [Apache License 2.0](LICENSE) (section 5:
  submissions are under the same license unless stated otherwise).
