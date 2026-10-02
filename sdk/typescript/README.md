# @delil/sdk

TypeScript SDK for [DƏLİL](https://github.com/serxan22/delil), cryptographically verifiable audit infrastructure.

```bash
npm install @delil/sdk
```

Node.js 20 or newer, zero runtime dependencies. Use it on servers only: API keys
must never reach browsers.

## Record an event

```ts
import { Delil } from "@delil/sdk";

const delil = new Delil({
  baseUrl: "http://localhost:8080",
  apiKey: process.env.DELIL_API_KEY,
});

const receipt = await delil.events.record({
  stream: "contracts",
  actor: { id: "user_128", type: "user", displayName: "Sarkhan Mahabbatli" },
  action: "contract.approved",
  resource: { type: "contract", id: "contract_813" },
  before: { status: "pending" },
  after: { status: "approved" },
  metadata: { requestId: "req_123" },
});
// { id: "evt_…", sequence: 1842, eventHash: "…", previousHash: "…", signature: "…", verificationStatus: "valid", … }
```

The server computes the structured diff, applies the project's redaction rules,
canonicalizes, hashes, links and signs the event before it answers.

## Safe retries

`record` and `recordBatch` always send an `Idempotency-Key` (a random UUID unless
you pass one), so the SDK can retry network errors and 429/502/503/504 without
ever creating duplicates. Pass your own key when the operation has a natural
identity, for example a webhook delivery id:

```ts
await delil.events.record(event, { idempotencyKey: `stripe:${webhookEvent.id}` });
```

Reads are retried too. Other writes (key rotation, exports) are never retried
automatically. Configure with `maxRetries` (default 2) and `timeoutMs`
(default 10 s per attempt).

## Read, verify, export

```ts
const page = await delil.events.list({ stream: "contracts", action: "contract.*", limit: 50 });
for await (const event of delil.events.iterate({ actorId: "user_128" })) { /* … */ }

const run = await delil.streams.verify("contracts");        // server-side verification
const report = await delil.events.verify(receipt.id);

const exp = await delil.exports.create({ stream: "contracts", from: "2026-09-01", to: "2026-10-01" });
await delil.exports.waitUntilReady(exp.id);
const zip = await delil.exports.download(exp.id);           // verify offline: delil verify-export
```

Server-side verification is a convenience. To verify without trusting the
server, use the `delil` CLI (`delil verify --trusted-keys trusted-keys.json`),
which downloads the raw chain and checks every hash and signature locally.

## Errors

| Class | When |
|---|---|
| `DelilValidationError` | 400/413/415/422; `details.errors` lists invalid fields |
| `DelilAuthenticationError` | 401 |
| `DelilPermissionError` | 403: the key lacks a scope |
| `DelilNotFoundError` | 404 (also for other tenants' resources) |
| `DelilConflictError` | 409 |
| `DelilRateLimitError` | 429, with `retryAfterMs` |
| `DelilTimeoutError`, `DelilNetworkError` | transport failures |

All API errors carry `status`, `code` and `requestId`.

## Development

```bash
npm install
npm test                 # unit tests (mocked fetch)
npm run build            # ESM + CJS + type declarations
DELIL_TEST_URL=http://localhost:8080 DELIL_TEST_API_KEY=dlk_… npm run test:integration
```
