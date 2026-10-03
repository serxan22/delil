# Security operations

How to run DƏLİL so that its guarantees hold in practice. The
[threat model](threat-model.md) explains what each measure defends against.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Checklist

- [ ] `DELIL_ENV=production`, TLS in front of the API and the dashboard.
- [ ] The server connects as a **runtime role** without `UPDATE`/`DELETE` on
      audit tables. Migrations use a separate owner role
      ([deployment](deployment.md#1-database-roles)).
- [ ] The master key comes from a secret manager, is not in images, repositories
      or database backups, and is backed up separately.
- [ ] `DELIL_ANCHOR_DIR` points at storage the database operators cannot rewrite
      (WORM bucket mount, another host), or witnesses are saved regularly by
      someone independent.
- [ ] Auditors keep a **pinned** `trusted-keys.json` and verify with the CLI, not
      only with the server.
- [ ] Alerts fire on `delil_verification_failures_total` and
      `INTEGRITY VERIFICATION FAILED` log lines.
- [ ] API keys are per application with minimal scopes, and have an expiry where
      possible.
- [ ] `/metrics` is internal or token-protected. `DELIL_TRUSTED_PROXIES` lists
      only your proxies.
- [ ] Release artifacts are checked: `sha256sum -c SHA256SUMS` and
      `gh attestation verify`.

## Database

- The runtime role (`delil_app`) has `SELECT, INSERT` on `audit_events`,
  `checkpoints` and `checkpoint_anchors`. Triggers additionally reject updates,
  deletes and truncation for every role except superusers and table owners,
  who can disable triggers.
- Restrict superuser and owner access to break-glass procedures, and log them
  (`log_statement = 'ddl'`, pgAudit). DƏLİL detects changes they make, but
  cannot stop them.
- Use TLS to the database (`sslmode=verify-full`).

## Signing keys

### Custody

- **`local` provider**: each project's Ed25519 seed is wrapped with
  AES-256-GCM under a key derived with HKDF-SHA256 from the master key, with the
  key id, tenant and project as authenticated data. A database dump alone
  reveals no signing key. A dump **plus** the master key reveals all of them.
- **`file` provider**: PKCS#8 PEM files in `DELIL_KEY_DIR`, mode 0600, mounted
  read-only from your secret store.
- KMS, HSM and remote-signer providers are on the roadmap. The `keys.Provider`
  interface and the data model already allow them.

### Rotation

Rotate on a schedule (for example yearly) and whenever people with key access
leave:

```bash
delil keys rotate                       # API key with keys:rotate
delil-server keys rotate --project …    # operators
```

Rotation waits for in-flight appends, activates a new key and retires the old
one. Old public keys are kept forever, so history keeps verifying. **Re-export
the trusted keys** after every rotation (`delil keys export`) and distribute
them to auditors.

### Revocation (suspected compromise)

```bash
curl -X POST "$DELIL_URL/v1/signing-keys/ed25519:…/revoke" \
  -H "Authorization: Bearer $DELIL_API_KEY" -H 'Content-Type: application/json' \
  -d '{"reason":"key material exposed in incident INC-123"}'
```

Revoking the active key creates a replacement. From then on, events signed by
the revoked key with a `recordedAt` after the revocation **fail** verification.
Events signed before it still verify, **but** an attacker holding the key could
have produced a whole alternative history in that period. Compare the chain
against witnesses and evidence packages taken before the suspected exposure, and
treat the period of possible compromise as suspect in your incident report.

## Witnesses and anchoring

Witnesses are what turn "the database says so" into "an independent party can
check it". They are the only defence against rollback and against an attacker
who holds both the database and a key.

- Set `DELIL_ANCHOR_DIR`. Every checkpoint is written there once
  (create-exclusive, mode 0440, never overwritten), organized by tenant,
  project and stream.
- Let auditors save witnesses on their own machines:
  `delil checkpoints save --stream contracts -o contracts-2026-10.json`.
  Verify later with `delil verify --witness contracts-2026-10.json`.
- Evidence packages also contain checkpoints. Keeping exported packages is a
  form of witnessing.

## Responding to a verification failure

A failed verification means the stored chain differs from what was signed. Do
**not** "fix" the data.

1. **Preserve**: snapshot the database and the server logs. Note the run id, the
   first failing sequence, and the failure codes (`delil verify --json`).
2. **Confirm independently**: run `delil verify --trusted-keys pinned.json`
   from a trusted machine, and compare against witnesses and earlier evidence
   packages.
3. **Scope**: the report's first failing sequence and codes tell you what kind
   of change happened (see the [attack catalogue](threat-model.md#attack-catalogue)).
   Everything after the first failure cannot be trusted through the current
   chain. Packages exported earlier still verify on their own and are your
   reference copy of that history.
4. **Investigate** database access around the time of the change: superuser
   logins, DDL, restores.
5. **Continue safely**: new events keep appending after the damaged ones, and
   the stream will keep failing verification from that point. Rotate keys if
   their exposure is possible. Record the incident; the failure itself is
   evidence and must stay visible.

## Application integration

- Keep API keys on servers only. Never ship them to browsers or mobile apps.
  Give each service its own key with only `events:write`.
- Send stable, pseudonymous identifiers (`user_128`), not emails, as actor ids.
  See [privacy](privacy.md).
- Use idempotency keys derived from your own identifiers (a request id, a
  webhook delivery id) so retries never duplicate or lose events
  ([example](../examples/webhook-audit)).
- Record before you acknowledge: if recording fails, fail the operation or
  queue it durably. Silently dropping audit events defeats the purpose.

## Supply chain

- Go modules are verified against `go.sum` and the checksum database. npm uses
  committed lockfiles with `npm ci`.
- CI runs govulncheck, `npm audit`, CodeQL, gitleaks and Trivy
  ([SECURITY.md](../SECURITY.md#how-the-project-is-checked)). Dependabot proposes
  updates weekly, and every GitHub Action is pinned to a commit SHA.
- Release binaries come with `SHA256SUMS` and SLSA build provenance. Images are
  multi-arch, distroless for the server and non-root for both, with SBOM and
  provenance attestations.
