import { createHmac } from "node:crypto";

/** The provider's signature scheme: HMAC-SHA256 over "<timestamp>.<raw body>". */
export function sign(secret: string, timestamp: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}
