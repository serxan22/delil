# webhook-audit

A webhook receiver that keeps a tamper-evident record of every delivery from a
(simulated) payment provider. Providers retry deliveries whenever they do not get
a timely 2xx, so naive auditing records duplicates. Silently dropping deliveries
is worse.

```bash
npm install
export DELIL_API_KEY=dlk_… WEBHOOK_SECRET=whsec_dev
npm start            # terminal 1: receiver on :4000
npm run send         # terminal 2: plays the provider
```

Expected output of `npm run send`:

```
delivery           → HTTP 200 {"received":true,"auditEventId":"evt_…","replayed":false}
provider retry     → HTTP 200 {"received":true,"auditEventId":"evt_…","replayed":true}
forged signature   → HTTP 401 {"error":"invalid signature"}
DƏLİL events for pay_…: 1 (expected 1)
```

## The pattern

1. **Authenticate first.** The receiver checks an HMAC-SHA256 signature over
   `timestamp.body` with a constant-time comparison and rejects timestamps
   outside a five-minute window.
2. **Use the provider's delivery id as the idempotency key**
   (`payments:<delivery id>`). A retried delivery returns the original receipt
   (`replayed: true`), so each delivery is in the audit trail exactly once.
3. **Acknowledge only after DƏLİL commits.** If recording fails the receiver
   answers 503 and the provider retries later. The idempotency key makes that
   retry safe.
4. **Audit rejections too.** A forged delivery is recorded as
   `webhook.rejected` with the reason and the SHA-256 of the body, not the
   attacker-controlled body itself.

`cardLast4` is stored as sent. Full card numbers (`cardNumber`), CVV and similar
members are redacted by the server's default denylist. Add your own keys or JSON
Pointer paths in the project's redaction settings.

| Variable | Default |
|---|---|
| `DELIL_API_KEY` | required (`events:write`, `events:read`) |
| `WEBHOOK_SECRET` | required; shared with the provider |
| `DELIL_URL` | `http://localhost:8080` |
| `DELIL_STREAM` | `payment-webhooks` |
| `PORT` | `4000` |
| `WEBHOOK_URL` | `http://localhost:4000/webhooks/payments` (sender only) |
