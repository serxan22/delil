// Plays the payment provider: sends a signed delivery, retries it (as
// providers do after a timeout) and sends one forged delivery. Then asks
// DƏLİL how many events exist for the payment: exactly one.
//
//   DELIL_API_KEY=dlk_... WEBHOOK_SECRET=whsec_dev npm run send
import { randomUUID } from "node:crypto";
import { Delil } from "@delil/sdk";
import { sign } from "./signature.ts";

const secret = process.env.WEBHOOK_SECRET;
const apiKey = process.env.DELIL_API_KEY;
if (!secret || !apiKey) {
  console.error("Set DELIL_API_KEY and WEBHOOK_SECRET.");
  process.exit(1);
}
const url = process.env.WEBHOOK_URL ?? "http://localhost:4000/webhooks/payments";
const paymentId = `pay_${randomUUID().slice(0, 8)}`;
const delivery = {
  id: `dlv_${randomUUID()}`,
  type: "payment.succeeded",
  createdAt: new Date().toISOString(),
  data: { object: "payment", id: paymentId, amount: 4900, currency: "AZN", customer: "cus_51", cardLast4: "4242" },
};

async function send(label: string, body: string, signatureSecret: string): Promise<void> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-webhook-timestamp": timestamp,
      "x-webhook-signature": sign(signatureSecret, timestamp, body),
    },
    body,
  });
  console.log(`${label.padEnd(18)} → HTTP ${res.status} ${await res.text()}`);
}

const body = JSON.stringify(delivery);
await send("delivery", body, secret);
await send("provider retry", body, secret);
await send("forged signature", body, "attacker-guess");

const delil = new Delil({ baseUrl: process.env.DELIL_URL ?? "http://localhost:8080", apiKey });
const page = await delil.events.list({ resourceType: "payment", resourceId: paymentId });
console.log(`DƏLİL events for ${paymentId}: ${page.data.length} (expected 1)`);
if (page.data.length !== 1) process.exit(2);
