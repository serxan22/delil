import { describe, expect, it, vi } from "vitest";
import {
  Delil,
  DelilAuthenticationError,
  DelilNetworkError,
  DelilNotFoundError,
  DelilPermissionError,
  DelilRateLimitError,
  DelilTimeoutError,
  DelilValidationError,
} from "../src/index.js";

type Call = { url: URL; init: RequestInit };

function mockFetch(responses: Array<Response | Error | ((c: Call) => Response | Promise<Response>)>) {
  const calls: Call[] = [];
  const fn = vi.fn(async (url: URL | string, init?: RequestInit) => {
    const call = { url: new URL(String(url)), init: init ?? {} };
    calls.push(call);
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next(call) : next;
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

const receipt = { object: "event_receipt", id: "evt_1", stream: "contracts", sequence: 1 };

function client(fetch: typeof globalThis.fetch, extra: Partial<ConstructorParameters<typeof Delil>[0]> = {}) {
  return new Delil({ baseUrl: "http://delil.test/", apiKey: "dlk_test", fetch, ...extra });
}

describe("events.record", () => {
  it("sends the event with auth and a generated idempotency key", async () => {
    const m = mockFetch([json(201, receipt)]);
    const r = await client(m.fn).events.record({
      stream: "contracts",
      actor: { id: "user_128", type: "user", displayName: "Sarkhan Mahabbatli" },
      action: "contract.approved",
      resource: { type: "contract", id: "contract_813" },
      before: { status: "pending" },
      after: { status: "approved" },
      occurredAt: new Date("2026-10-02T09:15:00Z"),
    });
    expect(r.id).toBe("evt_1");
    const { url, init } = m.calls[0]!;
    const headers = init.headers as Record<string, string>;
    expect(url.toString()).toBe("http://delil.test/v1/events");
    expect(init.method).toBe("POST");
    expect(headers.Authorization).toBe("Bearer dlk_test");
    expect(headers["Idempotency-Key"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.parse(init.body as string).occurredAt).toBe("2026-10-02T09:15:00.000Z");
  });

  it("retries transient failures with the same idempotency key", async () => {
    const m = mockFetch([new TypeError("socket hang up"), json(503, { error: { code: "unavailable", message: "x" } }), json(201, receipt)]);
    const r = await client(m.fn).events.record({ stream: "s", actor: { type: "user", id: "u" }, action: "a" }, { idempotencyKey: "k1" });
    expect(r.sequence).toBe(1);
    expect(m.calls).toHaveLength(3);
    const keys = m.calls.map((c) => (c.init.headers as Record<string, string>)["Idempotency-Key"]);
    expect(new Set(keys)).toEqual(new Set(["k1"]));
  });

  it("marks replayed responses", async () => {
    const m = mockFetch([json(201, receipt, { "Idempotent-Replayed": "true" })]);
    const r = await client(m.fn).events.record({ stream: "s", actor: { type: "user", id: "u" }, action: "a" });
    expect(r.replayed).toBe(true);
  });

  it("marks fresh receipts as not replayed", async () => {
    const m = mockFetch([json(201, receipt)]);
    const r = await client(m.fn).events.record({ stream: "s", actor: { type: "user", id: "u" }, action: "a" });
    expect(r.replayed).toBe(false);
  });

  it("copies the replay flag to every batch receipt", async () => {
    const page = { object: "list", data: [receipt, { ...receipt, sequence: 2 }] };
    const ev = { stream: "s", actor: { type: "user", id: "u" }, action: "a" };
    const m = mockFetch([json(201, page), json(201, page, { "Idempotent-Replayed": "true" })]);
    const c = client(m.fn);
    expect((await c.events.recordBatch([ev, ev])).map((r) => r.replayed)).toEqual([false, false]);
    expect((await c.events.recordBatch([ev, ev])).map((r) => r.replayed)).toEqual([true, true]);
  });
});

describe("retry safety", () => {
  it("never retries unsafe writes without an idempotency key", async () => {
    const m = mockFetch([json(503, { error: { code: "unavailable", message: "busy" } })]);
    await expect(client(m.fn).signingKeys.rotate()).rejects.toThrow("unavailable");
    expect(m.calls).toHaveLength(1);
  });

  it("does not retry client errors", async () => {
    const m = mockFetch([json(422, { error: { code: "invalid_event", message: "bad", details: { errors: [{ field: "stream" }] } } })]);
    const err = await client(m.fn).events.record({ stream: "S", actor: { type: "user", id: "u" }, action: "a" }).catch((e) => e);
    expect(err).toBeInstanceOf(DelilValidationError);
    expect(err.details.errors[0].field).toBe("stream");
    expect(m.calls).toHaveLength(1);
  });

  it("honours Retry-After on 429 and gives up after maxRetries", async () => {
    const limited = () => json(429, { error: { code: "rate_limited", message: "slow down" } }, { "Retry-After": "0" });
    const m = mockFetch([limited(), limited()]);
    const err = await client(m.fn, { maxRetries: 1 }).events.list().catch((e) => e);
    expect(err).toBeInstanceOf(DelilRateLimitError);
    expect(err.retryAfterMs).toBe(0);
    expect(m.calls).toHaveLength(2);
  });
});

describe("errors", () => {
  it.each([
    [401, DelilAuthenticationError],
    [403, DelilPermissionError],
    [404, DelilNotFoundError],
  ])("maps %i", async (status, cls) => {
    const m = mockFetch([json(status, { error: { code: "x", message: "y", requestId: "req_1" } })]);
    const err = await client(m.fn).events.get("evt_1").catch((e) => e);
    expect(err).toBeInstanceOf(cls);
    expect(err.requestId).toBe("req_1");
    expect(err.status).toBe(status);
  });

  it("reports network failures and timeouts", async () => {
    const m = mockFetch([new TypeError("ECONNREFUSED")]);
    await expect(client(m.fn, { maxRetries: 0 }).events.get("evt_1")).rejects.toBeInstanceOf(DelilNetworkError);
    const slow = mockFetch([
      (c) =>
        new Promise<Response>((_, reject) => c.init.signal?.addEventListener("abort", () => reject(c.init.signal?.reason))),
    ]);
    await expect(client(slow.fn, { maxRetries: 0, timeoutMs: 20 }).events.get("evt_1")).rejects.toBeInstanceOf(DelilTimeoutError);
  });

  it("requires credentials", () => {
    expect(() => new Delil({ baseUrl: "http://x", apiKey: undefined })).toThrow("apiKey is required");
  });
});

describe("pagination", () => {
  it("iterates across pages", async () => {
    const m = mockFetch([
      json(200, { object: "list", data: [{ id: "evt_3" }, { id: "evt_2" }], hasMore: true, nextCursor: "c1" }),
      json(200, { object: "list", data: [{ id: "evt_1" }], hasMore: false }),
    ]);
    const ids: string[] = [];
    for await (const e of client(m.fn).events.iterate({ stream: "contracts", limit: 2 })) ids.push(e.id);
    expect(ids).toEqual(["evt_3", "evt_2", "evt_1"]);
    expect(m.calls[1]!.url.searchParams.get("cursor")).toBe("c1");
    expect(m.calls[0]!.url.searchParams.get("stream")).toBe("contracts");
  });
});
