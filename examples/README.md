# Examples

Three small, runnable programs that use the [TypeScript SDK](../sdk/typescript).
Each one is standalone TypeScript run directly by Node.js (≥ 22.18, which strips
types natively), so there is no build step.

| Example | Shows |
|---|---|
| [`node-basic`](node-basic) | Record single and batched events, idempotent retries, redaction, validation errors, verification |
| [`webhook-audit`](webhook-audit) | A webhook receiver that authenticates deliveries and records each one **exactly once**, even when the provider retries |
| [`contract-workflow`](contract-workflow) | A contract lifecycle with before/after diffs, pinned keys, a signed checkpoint as a witness, and an evidence package verified offline |

## Setup (once)

```bash
# 1. Start DƏLİL and note the bootstrap API key
make dev                    # in another terminal, from the repository root
make credentials            # prints the API key (dlk_…) on first start

# 2. Build the SDK the examples link to
cd sdk/typescript && npm ci && npm run build && cd -

# 3. Install an example
cd examples/node-basic && npm install
export DELIL_API_KEY=dlk_…  # DELIL_URL defaults to http://localhost:8080
npm start
```

The bootstrap key has every scope. For real applications create a key with only
the scopes it needs (`events:write` for most services) in the dashboard under
**API keys**.

`npm run typecheck` checks an example against the SDK's types. CI type-checks all
three and runs them against a live server.
