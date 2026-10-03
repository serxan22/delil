# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may
contain breaking changes; integrity-relevant changes are always called out and
always keep existing chains verifiable.

## [Unreleased]

### Added
- `delil-bench`: offline engine benchmark (canonicalize, hash+sign, verify,
  tamper check) and HTTP load test with latency percentiles and local plus
  server-side verification of the written streams.
- `pkg/client`: `ChainSource` and `Client.VerifyStreamLocal` for verifying a
  stream without trusting the server (now shared by the CLI).
- Examples: `node-basic`, `webhook-audit` and `contract-workflow`.
- CI: Go lint and tests against PostgreSQL 16 and 18, test vectors, SDK,
  dashboard, OpenAPI lint, cross-compilation, and an end-to-end suite on the
  Compose stack that checks least privilege and tamper detection.
- Security workflow: govulncheck, gitleaks, npm audit, CodeQL and Trivy.
  Release workflow with checksums, SLSA provenance and multi-arch images.
- Documentation, security policy, contribution guide, code of conduct and
  issue and pull request templates.
- A test that fails when `api/openapi.yaml` and the router disagree.

### Changed
- OpenAPI document: every operation documents its error responses, and list,
  session and user responses have schemas. It now lints clean.
- Dashboard image: the runtime stage no longer ships npm, npx, corepack or
  yarn, removing every HIGH finding Trivy reported in the base image.

### Fixed
- SDK: `events.record` returned `replayed: undefined` instead of `false` for
  new events, and `events.recordBatch` never set `replayed` on its receipts.

## [0.1.0] - unreleased

The first version. Highlights:

- RFC 8785 canonical JSON (strict I-JSON input profile), SHA-256 with domain
  separation, per-stream hash chains and Ed25519 signatures with key rotation
  and revocation. Published test vectors are reproduced by an independent
  Node.js implementation.
- Verification engine that reports the first and every failure with sequence,
  code and expected/found values (payload, header, link, signature, ordering,
  checkpoint, head, truncation and rollback checks).
- PostgreSQL storage: append-only triggers, a least-privilege runtime role,
  concurrent-append safety, atomic batches and race-safe idempotency.
- Signed checkpoints, optional file anchoring, and evidence packages (ZIP) with
  selective disclosure that verify offline.
- REST API with tenant isolation, scoped API keys, rate limiting and
  Prometheus metrics; `delil` CLI with independent local verification;
  TypeScript SDK; Next.js dashboard; Docker Compose stack and tamper demo.

[Unreleased]: https://github.com/serxan22/delil/compare/06dff89...HEAD
