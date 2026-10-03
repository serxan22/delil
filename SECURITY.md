# Security policy

DƏLİL exists to make tampering with audit records detectable. A flaw that lets
someone alter, insert, delete or reorder records **without** verification
failing is the most serious class of bug in this project, and we treat it that
way.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/serxan22/delil/security/advisories/new)
(repository → *Security* → *Report a vulnerability*).

Please include:

- the affected component and version (`delil version`, image tag or commit);
- a description of the impact and the conditions an attacker needs;
- a minimal reproduction: a script, a modified evidence package, or the
  verification report showing the wrong result;
- whether you want to be credited, and how.

Never include real audit data, production API keys or master keys.

### What to expect

| | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix for critical issues (verification bypass, cross-tenant access, key disclosure) | as fast as possible, normally within 30 days |
| Public advisory | after a fix is released, coordinated with you |

We will keep you informed and credit you in the advisory unless you prefer
otherwise. We will not take legal action against good-faith research that
respects this policy: test only against your own deployment, avoid privacy
violations and service disruption, and give us reasonable time to fix the issue
before disclosure.

## Supported versions

DƏLİL is pre-1.0. Security fixes are released for the latest minor version only.

| Version | Supported |
|---|---|
| 0.1.x | ✓ |

## Scope

In scope, in rough order of severity:

1. **Verification bypass**: modified, inserted, deleted, reordered or truncated
   records that verify as valid with `pkg/verify`, the CLI or `delil verify-export`.
   This includes canonicalization ambiguities (two different contents with the same
   canonical form) and signature or hash confusion across domains.
2. **Key compromise**: disclosure of private signing keys or the master key, or
   signing with a retired or revoked key without detection.
3. **Tenant isolation**: reading or writing another organization's or project's
   data.
4. **Authentication and authorization**: API key scope escalation, session
   fixation or theft, login rate-limit bypass.
5. **Evidence packages**: zip-slip, decompression bombs, or a package that makes
   the offline verifier read outside the package or exhaust memory.
6. **Redaction**: values matching redaction rules that are persisted or hashed.

Out of scope: an attacker with PostgreSQL superuser **and** the signing keys
rewriting history that has never been checkpointed or exported (see the
[threat model](docs/threat-model.md); this is why external witnesses exist),
denial of service by an authenticated tenant within its configured limits, and
findings that require a modified client or browser.

## How the project is checked

Every push and pull request runs:

- `go test -race` against real PostgreSQL 16 and 18, including a tamper-detection
  suite, plus an end-to-end run that edits a stored record and requires
  verification to fail at that exact sequence;
- `golangci-lint` with `gosec`, CodeQL (`security-extended`) for Go and
  TypeScript, and `govulncheck`;
- `gitleaks` over the full git history;
- `npm audit` for every Node.js package, and Trivy for both container images
  (fails on fixable HIGH or CRITICAL findings);
- cross-implementation test vectors: an independent Node.js implementation must
  reproduce every hash and signature in `docs/test-vectors.json`.

Release binaries and container images carry SLSA build provenance attestations
(`gh attestation verify`).

### Accepted advisories

Advisories in **development-only** dependencies that cannot reach production are
reported by CI but do not fail it. The current list:

| Package | Advisory | Why it is accepted |
|---|---|---|
| `braces` (via `eslint-config-next` → `fast-glob` → `micromatch`), dashboard | GHSA-vfj7-8cjw-p6xm | Lint-time only; glob patterns come from the repository's own config. No fixed `braces` release exists yet; `npm audit --omit=dev` is clean and the runtime image contains no dev dependencies. |
| `esbuild` 0.27 (via `tsup`, `vitest`), SDK | GHSA-g7r4-m6w7-qqqr | Affects esbuild's development server on Windows, which is never started; the SDK has no runtime dependencies. `tsup` pins `esbuild@^0.27`. |

Runtime dependencies must have no known advisories.

CodeQL findings fail the build unless they are listed, with a reason and a
review date, in [`.github/codeql/accepted-findings.json`](.github/codeql/accepted-findings.json).
Today that list has one entry: `delil-server users create` deliberately
prints a password it generated once, to the operator's terminal.

## Hardening guidance

See [docs/security.md](docs/security.md) for deployment hardening: database
roles, master-key handling, TLS, key rotation and revocation, checkpoint
anchoring and monitoring.
