// Runs against a real server: DELIL_TEST_URL and DELIL_TEST_API_KEY must be set.
import { describe, expect, it } from "vitest";
import { Delil, DelilNotFoundError } from "../src/index.js";

const url = process.env.DELIL_TEST_URL;
const key = process.env.DELIL_TEST_API_KEY;

describe.skipIf(!url || !key)("live server", () => {
  const delil = new Delil({ baseUrl: url ?? "", apiKey: key });
  const stream = `sdk-it-${Date.now()}`;

  it("records, reads, verifies and exports", async () => {
    const r1 = await delil.events.record({
      stream, actor: { type: "user", id: "user_128", displayName: "Sarkhan Mahabbatli" }, action: "contract.approved",
      resource: { type: "contract", id: "contract_813" }, before: { status: "pending" }, after: { status: "approved" },
      metadata: { requestId: "req_123" },
    }, { idempotencyKey: `${stream}-1` });
    expect(r1.sequence).toBe(1);
    expect(r1.verificationStatus).toBe("valid");
    const again = await delil.events.record({
      stream, actor: { type: "user", id: "user_128", displayName: "Sarkhan Mahabbatli" }, action: "contract.approved",
      resource: { type: "contract", id: "contract_813" }, before: { status: "pending" }, after: { status: "approved" },
      metadata: { requestId: "req_123" },
    }, { idempotencyKey: `${stream}-1` });
    expect(again.id).toBe(r1.id);
    expect(again.replayed).toBe(true);

    const batch = await delil.events.recordBatch([
      { stream, actor: { type: "service", id: "billing" }, action: "invoice.issued", data: { amount: 120.5 } },
      { stream, actor: { type: "service", id: "billing" }, action: "payment.received", data: { card_number: "4111111111111111" } },
    ]);
    expect(batch.map((r) => r.sequence)).toEqual([2, 3]);

    const ev = await delil.events.get(batch[1]!.id);
    expect(ev.data).toEqual({ card_number: "[REDACTED]" });
    expect(ev.changes).toBeUndefined();
    expect((await delil.events.get(r1.id)).changes).toEqual([{ op: "replace", path: "/status", from: "pending", to: "approved" }]);

    const run = await delil.streams.verify(stream);
    expect(run.status).toBe("passed");
    expect(run.eventsChecked).toBe(3);
    expect((await delil.events.verify(r1.id)).valid).toBe(true);

    const x = await delil.exports.create({ stream });
    const done = await delil.exports.waitUntilReady(x.id, { intervalMs: 200 });
    expect(done.disclosedEvents).toBe(3);
    const zip = await delil.exports.download(x.id);
    expect(zip[0]).toBe(0x50); // "PK"

    await expect(delil.events.get("evt_00000000000000000000000000")).rejects.toBeInstanceOf(DelilNotFoundError);
  });
});
