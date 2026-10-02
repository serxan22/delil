#!/usr/bin/env node
// Independently verifies docs/test-vectors.json with Node's own SHA-256,
// Ed25519 and a minimal RFC 8785 serializer — no DƏLİL code involved. If this
// script and the Go implementation ever disagree, the construction is not
// reproducible and must not ship.
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";

const vectors = JSON.parse(readFileSync(new URL("../docs/test-vectors.json", import.meta.url)));

// RFC 8785: JSON.stringify already produces ECMAScript number and string
// serialization; JCS only adds member sorting by UTF-16 code units, which is
// JavaScript's default string ordering.
function jcs(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
}

const tagged = (tag, data) =>
  createHash("sha256").update(Buffer.concat([Buffer.from(tag, "ascii"), Buffer.from([0]), Buffer.from(data)])).digest();

const rawPub = Buffer.from(vectors.signingKey.publicKeyBase64, "base64");
const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: rawPub.toString("base64url") }, format: "jwk" });
const fingerprint = createHash("sha256").update(rawPub).digest("hex");

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failures++;
};

check(fingerprint === vectors.signingKey.fingerprint, "public key fingerprint");
check(`ed25519:${fingerprint.slice(0, 32)}` === vectors.signingKey.keyId, "key id derivation");

let previous = "0".repeat(64);
for (const ev of vectors.events) {
  const canonical = jcs(ev.content);
  check(canonical === ev.contentCanonical, `${ev.name}: content canonicalization`);
  check(tagged("delil:v1:payload", canonical).toString("hex") === ev.payloadHash, `${ev.name}: payload hash`);
  check(jcs(ev.header) === ev.headerCanonical, `${ev.name}: header canonicalization`);
  check(ev.header.payloadHash === ev.payloadHash, `${ev.name}: header commits to payload hash`);
  check(ev.header.previousHash === previous, `${ev.name}: chain linkage`);
  const eventHash = tagged("delil:v1:event", ev.headerCanonical);
  check(eventHash.toString("hex") === ev.eventHash, `${ev.name}: event hash`);
  const message = Buffer.concat([Buffer.from("delil:v1:event-signature", "ascii"), Buffer.from([0]), eventHash]);
  check(message.toString("hex") === ev.signingMessageHex, `${ev.name}: signing message`);
  check(verify(null, message, publicKey, Buffer.from(ev.signatureBase64, "base64")), `${ev.name}: Ed25519 signature`);
  previous = ev.eventHash;
}

const cp = vectors.checkpoint;
check(jcs(cp.body) === cp.bodyCanonical, "checkpoint canonicalization");
const cpHash = tagged("delil:v1:checkpoint", cp.bodyCanonical);
check(cpHash.toString("hex") === cp.checkpointHash, "checkpoint hash");
check(cp.body.headHash === previous, "checkpoint commits to the chain head");
const cpMessage = Buffer.concat([Buffer.from("delil:v1:checkpoint-signature", "ascii"), Buffer.from([0]), cpHash]);
check(verify(null, cpMessage, publicKey, Buffer.from(cp.signatureBase64, "base64")), "checkpoint signature");

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll test vectors verified independently with Node.js crypto.");
