// webhook-audit: a webhook receiver that records every delivery in DƏLİL
// exactly once, even when the provider retries.
//
//   DELIL_API_KEY=dlk_... WEBHOOK_SECRET=whsec_dev npm start
//
// The pattern:
//   1. Authenticate the delivery (HMAC-SHA256 over timestamp + raw body,
//      constant-time comparison, 5-minute replay window).
//   2. Record it in DƏLİL with the provider's delivery id as the idempotency
//      key. A retried delivery returns the original receipt; no duplicate.
//   3. Acknowledge (2xx) only after DƏLİL has committed. If auditing fails the
//      provider retries later, so no delivery is processed without a record.
//   4. Record rejected deliveries too: forged webhooks are security events.
import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Delil, DelilApiError } from "@delil/sdk";
import { sign } from "./signature.ts";

const apiKey = process.env.DELIL_API_KEY;
const secret = process.env.WEBHOOK_SECRET;
if (!apiKey || !secret) {
  console.error("Set DELIL_API_KEY and WEBHOOK_SECRET (see this example's README).");
  process.exit(1);
}
const delil = new Delil({ baseUrl: process.env.DELIL_URL ?? "http://localhost:8080", apiKey });
const stream = process.env.DELIL_STREAM ?? "payment-webhooks";
const port = Number(process.env.PORT ?? 4000);
const maxBody = 256 * 1024;
const toleranceSeconds = 300;

interface Delivery {
  id: string;
  type: string;
  createdAt: string;
  data: { object: string; id: string; [key: string]: unknown };
}

function authentic(timestamp: string | undefined, signature: string | undefined, body: string): string | null {
  if (!timestamp || !signature) return "missing signature headers";
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > toleranceSeconds) return "timestamp outside the replay window";
  const expected = Buffer.from(sign(secret!, timestamp, body));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return "signature mismatch";
  return null;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > maxBody) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function reply(res: ServerResponse, status: number, body: object): void {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== "POST" || req.url !== "/webhooks/payments") return reply(res, 404, { error: "not found" });
  const sourceIp = req.socket.remoteAddress;
  const userAgent = req.headers["user-agent"]?.slice(0, 512);
  let body: string;
  try {
    body = await readBody(req);
  } catch {
    return reply(res, 413, { error: "body too large" });
  }

  const problem = authentic(req.headers["x-webhook-timestamp"] as string, req.headers["x-webhook-signature"] as string, body);
  if (problem) {
    // Never record the unauthenticated body: it is attacker-controlled. Its
    // hash is enough to correlate with the provider later.
    await delil.events.record({
      stream,
      actor: { type: "external", id: "unauthenticated" },
      action: "webhook.rejected",
      data: { reason: problem, bodySha256: createHash("sha256").update(body).digest("hex") },
      context: { sourceIp, userAgent },
    }).catch((err) => console.error("could not audit a rejected webhook:", err));
    return reply(res, 401, { error: "invalid signature" });
  }

  let delivery: Delivery;
  try {
    delivery = JSON.parse(body);
    if (typeof delivery.id !== "string" || typeof delivery.type !== "string" || !delivery.data?.id) throw new Error();
  } catch {
    return reply(res, 400, { error: "malformed delivery" });
  }

  try {
    const receipt = await delil.events.record(
      {
        stream,
        actor: { type: "service", id: "payment-provider" },
        action: `webhook.${delivery.type}`,
        resource: { type: delivery.data.object, id: delivery.data.id },
        data: { deliveryId: delivery.id, ...delivery.data },
        occurredAt: delivery.createdAt,
        context: { requestId: delivery.id, sourceIp, userAgent },
      },
      { idempotencyKey: `payments:${delivery.id}` },
    );
    console.log(`${delivery.id} → ${receipt.id} #${receipt.sequence}${receipt.replayed ? " (replayed retry)" : ""}`);
    // ... process the delivery here (fulfil the order, update the ledger) ...
    return reply(res, 200, { received: true, auditEventId: receipt.id, replayed: receipt.replayed });
  } catch (err) {
    const code = err instanceof DelilApiError ? err.code : String(err);
    console.error(`could not audit ${delivery.id}: ${code}`);
    // 503 makes the provider retry; the idempotency key keeps the retry safe.
    return reply(res, 503, { error: "audit unavailable, retry later" });
  }
}

createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) reply(res, 500, { error: "internal error" });
  });
}).listen(port, () => console.log(`webhook receiver on http://localhost:${port}/webhooks/payments → DƏLİL stream "${stream}"`));
