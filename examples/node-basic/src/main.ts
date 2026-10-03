// node-basic: record events with the DƏLİL TypeScript SDK, read them back and
// verify them.
//
//   DELIL_API_KEY=dlk_... npm start
import { Delil, DelilValidationError } from "@delil/sdk";

const apiKey = process.env.DELIL_API_KEY;
if (!apiKey) {
  console.error("Set DELIL_API_KEY (see this example's README).");
  process.exit(1);
}

const delil = new Delil({ baseUrl: process.env.DELIL_URL ?? "http://localhost:8080", apiKey });
const stream = process.env.DELIL_STREAM ?? "examples-basic";

// 1. One event. The server diffs before/after, redacts sensitive members,
//    canonicalizes (RFC 8785), hashes, links and signs before it answers.
const receipt = await delil.events.record({
  stream,
  actor: { type: "user", id: "user_128", displayName: "Aysel Mammadova" },
  action: "invoice.approved",
  resource: { type: "invoice", id: "inv_2026_0042" },
  before: { status: "pending", amount: 1250, currency: "AZN" },
  after: { status: "approved", amount: 1250, currency: "AZN", approvedBy: "user_128" },
  metadata: { requestId: "req_7f3a" },
  context: { requestId: "req_7f3a", sourceIp: "203.0.113.7", userAgent: "node-basic-example" },
});
console.log(`recorded ${receipt.id} as ${stream} #${receipt.sequence}`);
console.log(`  eventHash    ${receipt.eventHash}`);
console.log(`  previousHash ${receipt.previousHash}`);
console.log(`  signed by    ${receipt.signingKeyId}`);

// 2. Safe retries: the same idempotency key returns the original receipt
//    instead of recording a duplicate.
const key = `example:${receipt.id}:comment`;
const comment = {
  stream,
  actor: { type: "user", id: "user_128" },
  action: "invoice.commented",
  resource: { type: "invoice", id: "inv_2026_0042" },
  data: { text: "Approved within budget." },
};
const first = await delil.events.record(comment, { idempotencyKey: key });
const retry = await delil.events.record(comment, { idempotencyKey: key });
console.log(`retry with the same key → same event: ${first.id === retry.id} (replayed: ${retry.replayed})`);

// 3. A batch is atomic: every event is committed or none is.
const batch = await delil.events.recordBatch([
  { stream, actor: { type: "service", id: "billing-worker" }, action: "invoice.sent", resource: { type: "invoice", id: "inv_2026_0042" } },
  { stream, actor: { type: "service", id: "billing-worker" }, action: "invoice.paid", resource: { type: "invoice", id: "inv_2026_0042" },
    data: { method: "bank_transfer", password: "never-stored" } },
]);
console.log(`batch committed sequences ${batch.map((r) => r.sequence).join(", ")}`);

// 4. Read back. "password" was redacted by the default denylist before hashing.
const paid = await delil.events.get(batch[1].id);
console.log(`stored data: ${JSON.stringify(paid.data)} (redacted: ${paid.redactions?.join(", ") || "none"})`);
const approved = await delil.events.get(receipt.id);
console.log(`computed changes: ${JSON.stringify(approved.changes)}`);

// 5. Validation errors list every invalid field.
try {
  await delil.events.record({ stream: "Not A Valid Stream!", actor: { type: "user", id: "" }, action: "" });
} catch (err) {
  if (!(err instanceof DelilValidationError)) throw err;
  console.log(`rejected invalid event: ${err.code}`);
}

// 6. Verify. events.verify checks one event and its neighbours; streams.verify
//    recomputes the whole chain on the server. For verification that does not
//    trust the server, use the CLI: `delil verify --stream <name>`.
const report = await delil.events.verify(receipt.id);
console.log(`event verification: ${report.result}`);
const run = await delil.streams.verify(stream);
console.log(`stream verification: ${run.status} (${run.eventsChecked} events checked)`);
if (run.status !== "passed") process.exit(2);
