# node-basic

The smallest useful DƏLİL integration: record events, retry safely, read them
back and verify them.

```bash
npm install
DELIL_API_KEY=dlk_… npm start
```

What it does, in order:

1. **Records an event** with `before`/`after` state. The server computes the
   diff, canonicalizes the content (RFC 8785), hashes it, links it to the previous
   event in the stream and signs it with Ed25519, and returns the receipt.
2. **Retries with the same idempotency key** and gets the original receipt back
   (`replayed: true`) instead of a duplicate.
3. **Records a batch** atomically. One event carries a `password` member, which
   the default denylist redacts *before* hashing. The secret never reaches the
   database.
4. **Reads the events back**, including the computed `changes` and the list of
   redacted paths.
5. **Sends an invalid event** and catches `DelilValidationError`.
6. **Verifies** one event and then the whole stream on the server.

Server-side verification is convenient, but it trusts the server. To check the
same stream without that trust, use the CLI, which downloads the raw chain and
recomputes every hash and signature locally:

```bash
delil keys export > trusted-keys.json        # once, store it safely
delil verify --stream examples-basic --trusted-keys trusted-keys.json
```

| Variable | Default |
|---|---|
| `DELIL_API_KEY` | required (`events:write`, `events:read`, `verify`) |
| `DELIL_URL` | `http://localhost:8080` |
| `DELIL_STREAM` | `examples-basic` |
