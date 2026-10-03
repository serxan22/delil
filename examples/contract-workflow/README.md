# contract-workflow

Audits a contract from draft to signature and produces everything a third party
(an auditor, a court, a counterparty) needs to check the record **without
trusting your server**.

```bash
npm install
DELIL_API_KEY=dlk_… npm start
```

The key needs `events:write`, `events:read`, `verify`, `exports` and `keys:read`.

## What happens

1. `contract.created` (with `before: null`) → `amount_changed` → `submitted` →
   `approved` → `signed`. Each transition sends the full before and after state.
   DƏLİL stores the field-level diff and hashes it into the stream's chain.
2. The counterparty's `apiToken` is redacted on ingestion by the default
   denylist. The IBAN is kept. Add `iban` to the project's redaction keys if your
   policy requires it.
3. `out/trusted-keys.json`: the project's public signing keys. Store them
   somewhere the DƏLİL server cannot write to. Verifying against pinned keys
   means a compromised server cannot re-sign a rewritten history.
4. `out/checkpoint.json`: a signed statement of the stream head. If events up
   to that point are later deleted or rewritten, `--witness` detects it, even if
   the attacker also rewrote the database's own checkpoints.
5. `out/<contract>.zip`: an evidence package. It holds the integrity skeleton
   of the whole stream range plus the content of **this contract's events only**
   (selective disclosure), signed by the project key.

## Verify like an auditor

```bash
# Offline: no server, no database, only the package and the pinned keys
delil verify-export out/contract_….zip --trusted-keys out/trusted-keys.json

# Online, but trusting only the pinned keys and the saved checkpoint
delil verify --stream contracts --trusted-keys out/trusted-keys.json --witness out/checkpoint.json
```

Both exit with status 0 when everything is intact and 1 when tampering is
detected, so they work in scripts and CI.
