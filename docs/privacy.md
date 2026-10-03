# Privacy and data protection

Audit logs record who did what, so they almost always contain personal data.
An append-only, tamper-evident log also makes it hard to correct or erase that
data later. This document explains how DƏLİL limits what is stored, and the
tensions you need to plan for. It is guidance, not legal advice.

## What DƏLİL stores

| Data | Where | Personal data? |
|---|---|---|
| Event content: actor, action, resource, before/after, diff, `data`, `metadata` | `audit_events.content`, hashed and signed | whatever your application sends |
| Request context: `requestId`, `traceId`, `sessionId`, `sourceIp`, `userAgent` | inside the content, when sent | IP addresses and user agents usually are |
| Dashboard users: email, display name, Argon2id password hash, last login | `users` | yes |
| Dashboard sessions: token hash, IP, user agent, timestamps | `sessions`, removed 24 h after expiry | yes |
| API keys: name, scopes, SHA-256 of the key, last use | `api_keys` | no, unless named after people |
| Server logs: request ids, routes, statuses, user and session ids on login | stdout | pseudonymous identifiers and IPs |

Event content, secrets and tokens are never written to logs.

## Minimise before you send

The most effective protection is not sending personal data at all.

- **Use pseudonymous, stable identifiers** for actors and resources
  (`user_128`, not an email). The mapping from identifier to person lives in
  your application, where it can be corrected and erased.
- Keep `displayName` optional. It is convenient in the dashboard, but it is
  personal data frozen into the chain.
- Send only the fields that matter for the audit trail in `before`/`after`, not
  whole database rows.

## Redaction on ingestion

Before an event is canonicalized and hashed, the server redacts sensitive
members in `before`, `after`, `data`, `metadata` and the computed diff.
Redacted values are never stored or hashed. The content lists them in
`redactions` (JSON Pointers), so the record shows that something was removed.

- **Default denylist** (case- and punctuation-insensitive member names):
  `password`, `passwd`, `pwd`, `passphrase`, `secret`, `clientSecret`, `token`,
  `accessToken`, `refreshToken`, `idToken`, `sessionToken`, `csrfToken`,
  `apiKey`, `xApiKey`, `authorization`, `proxyAuthorization`, `cookie`,
  `setCookie`, `privateKey`, `creditCard`, `creditCardNumber`, `cardNumber`,
  `cvv`, `cvc`, `ssn`, `otp`, `mfaCode`, `totp`, `pin`. Names *ending* in
  `password`, `secret`, `token`, `apiKey` or `privateKey` (such as
  `githubToken`) are also redacted. `secretary` is not.
- **Project rules** (dashboard → Settings, or `PATCH /v1/project`): extra member
  names (`keys`), exact JSON Pointers (`paths`, e.g. `/after/customer/iban`),
  and the mode:
  - `redact` (default): replace the value with `"[REDACTED]"`;
  - `remove`: drop the member;
  - `mask`: keep the last four characters of strings.
- `disableDefaults` turns the built-in list off. Don't, unless you replace it.

`context` (request id, trace id, session id, source IP, user agent) is stored
as sent and is not subject to redaction: omit fields you do not want kept.

The diff is computed on the unredacted states and then redacted. A change to a
sensitive field is therefore visible (`/after/password` changed) without its
values.

## Store the change, not the state

With `retainStates: "diff"` in the project settings, the server computes the
diff and then discards `before` and `after`. Only the changed fields (redacted
as above) are kept. This is often enough for an audit trail and stores far less.

## Erasure and correction

Changing or deleting a committed event breaks verification. That is the
point of the system, and it collides with rights such as erasure (GDPR
Art. 17) and rectification (Art. 16). Plan for it:

1. **Prevention** (above) is the main control: an audit log that holds only
   pseudonymous ids and minimal fields rarely needs erasure.
2. **Legal basis and retention**: audit logs are commonly kept under a legal
   obligation or legitimate interest, which can limit erasure requests. Define a
   retention period per stream with your DPO and document it.
3. **Corrections** are recorded as *new* events (`profile.corrected`) that
   reference the original. The history stays intact and the correction is
   itself audited.
4. **Content erasure with tombstones** is on the roadmap. Because the chain
   commits to `payloadHash` rather than to the content, a future version can
   delete an event's content and keep its header: the chain still verifies, and
   the gap is visible and attributable. Until then, erasing content means
   accepting a documented verification failure at that sequence.

## Sharing evidence

Evidence packages support **selective disclosure**. The integrity skeleton
(headers only) covers the whole range, but content is included only for events
matching the export filters (actor, action, resource). A court or counterparty
can verify that the disclosed events sit in an intact chain without seeing
unrelated people's records. Check the filters before sending a package: the
skeleton itself reveals event ids, timestamps and counts.

## Access within DƏLİL

- Tenants are isolated. Dashboard roles (`admin`, `auditor`, `viewer`) and API
  key scopes limit who reads events. `viewer` and `auditor` cannot change
  settings or keys.
- Exports require the `exports` scope and expire (`DELIL_EXPORT_TTL`, 7 days by
  default).
- Reading audit data is not itself audited inside DƏLİL yet. Use your reverse
  proxy's access logs if you need that.

## Processing records

If you operate DƏLİL for others, it is a processor of their audit data. Your
records of processing should mention: the categories above, retention per
stream, where the database, backups, exports and anchor storage live
(transfers), and the measures in [security](security.md).
