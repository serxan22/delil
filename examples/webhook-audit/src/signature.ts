import { createHmac } from "node:crypto";

/** The provider's signature scheme: HMAC-SHA256 over "<timestamp>." followed by the raw body bytes. */
export function sign(secret: string, timestamp: string, body: Buffer | string): string {
  return "sha256=" + createHmac("sha256", secret).update(`${timestamp}.`).update(body).digest("hex");
}
