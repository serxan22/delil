// contract-workflow: audit a contract's lifecycle, pin the signing keys, save a
// signed checkpoint as an independent witness, and produce an evidence
// package that a third party can verify offline.
//
//   DELIL_API_KEY=dlk_... npm start
//
// Writes into ./out/:
//   trusted-keys.json      public keys to pin   (delil verify --trusted-keys)
//   checkpoint.json        a signed head        (delil verify --witness)
//   <contract>.zip         the evidence package (delil verify-export)
import { mkdir, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { Delil, type Actor, type JsonValue } from "@delil/sdk";

const apiKey = process.env.DELIL_API_KEY;
if (!apiKey) {
  console.error("Set DELIL_API_KEY with the events:write, events:read, verify, exports and keys:read scopes.");
  process.exit(1);
}
const delil = new Delil({ baseUrl: process.env.DELIL_URL ?? "http://localhost:8080", apiKey });
const stream = process.env.DELIL_STREAM ?? "contracts";
const outDir = new URL("../out/", import.meta.url);

type Status = "draft" | "in_review" | "approved" | "signed";
interface Contract {
  id: string;
  title: string;
  status: Status;
  amount: number;
  currency: string;
  counterparty: { name: string; iban: string; apiToken?: string };
  approvals: string[];
}

const lawyer: Actor = { type: "user", id: "user_204", displayName: "Leyla Huseynova" };
const manager: Actor = { type: "user", id: "user_128", displayName: "Sarkhan Mahabbatli" };
const signer: Actor = { type: "service", id: "esign-service" };

// The application owns the state. Each transition records before/after; the
// server computes the field-level diff and hashes it into the chain.
async function transition(contract: Contract, actor: Actor, action: string, change: (c: Contract) => void, data?: JsonValue) {
  const before = structuredClone(contract);
  change(contract);
  const receipt = await delil.events.record({
    stream,
    actor,
    action,
    resource: { type: "contract", id: contract.id, displayName: contract.title },
    before: before as unknown as JsonValue,
    after: structuredClone(contract) as unknown as JsonValue,
    data,
    context: { requestId: `req_${randomUUID().slice(0, 8)}` },
  });
  console.log(`  #${String(receipt.sequence).padEnd(5)} ${action.padEnd(22)} ${receipt.eventHash.slice(0, 16)}…`);
}

const contract: Contract = {
  id: `contract_${randomUUID().slice(0, 8)}`,
  title: "Office lease — Baku, Nizami St.",
  status: "draft",
  amount: 18000,
  currency: "AZN",
  counterparty: { name: "Caspian Properties LLC", iban: "AZ21NABZ00000000137010001944", apiToken: "cp_live_should_never_be_stored" },
  approvals: [],
};

console.log(`Contract ${contract.id} → stream "${stream}"`);
await delil.events.record({
  stream, actor: lawyer, action: "contract.created",
  resource: { type: "contract", id: contract.id, displayName: contract.title },
  before: null, // null: the resource did not exist
  after: structuredClone(contract) as unknown as JsonValue,
});
await transition(contract, lawyer, "contract.amount_changed", (c) => { c.amount = 17500; }, { reason: "negotiated discount" });
await transition(contract, lawyer, "contract.submitted", (c) => { c.status = "in_review"; });
await transition(contract, manager, "contract.approved", (c) => { c.status = "approved"; c.approvals.push(manager.id); });
await transition(contract, signer, "contract.signed", (c) => { c.status = "signed"; }, { envelopeId: "env_93c1", method: "qualified-e-signature" });

// Default redaction removed the token before hashing; the diff still shows
// the amount change.
const events = await delil.events.list({ resourceType: "contract", resourceId: contract.id });
const created = events.data.find((e) => e.action === "contract.created")!;
const amended = events.data.find((e) => e.action === "contract.amount_changed")!;
console.log(`redacted on ingestion: ${created.redactions?.join(", ")}`);
console.log(`diff of the amendment: ${JSON.stringify(amended.changes)}`);

await mkdir(outDir, { recursive: true });

// 1. Pin the public keys. Keep this file somewhere the server cannot modify:
//    verifying with pinned keys means a compromised server cannot re-sign history.
await writeFile(new URL("trusted-keys.json", outDir), JSON.stringify(await delil.signingKeys.export(), null, 2));

// 2. Sign the current head and keep it as a witness. If anyone later deletes
//    or rewrites events up to this point, `delil verify --witness` notices.
const checkpoint = await delil.streams.createCheckpoint(stream);
await writeFile(new URL("checkpoint.json", outDir), JSON.stringify(checkpoint, null, 2));
console.log(`checkpoint at sequence ${checkpoint.sequence}: ${checkpoint.headHash.slice(0, 16)}…`);

// 3. Evidence package: the whole chain's integrity skeleton plus the content
//    of this contract's events only (selective disclosure).
const exp = await delil.exports.create({ stream, resourceType: "contract", resourceId: contract.id });
const ready = await delil.exports.waitUntilReady(exp.id, { intervalMs: 500 });
if (ready.status !== "completed") throw new Error(`export ${ready.status}: ${ready.error ?? ""}`);
const zip = await delil.exports.download(exp.id);
const file = new URL(`${contract.id}.zip`, outDir);
await writeFile(file, zip);
const sha256 = createHash("sha256").update(zip).digest("hex");
console.log(`evidence package: out/${contract.id}.zip (${zip.byteLength} bytes, sha256 ${sha256.slice(0, 16)}…)`);
console.log(`  ${ready.disclosedEvents} of ${ready.chainEvents} chain events disclosed; server check: ${ready.verificationValid ? "valid" : "INVALID"}`);
if (sha256 !== ready.sha256) throw new Error("downloaded package does not match the server's hash");

console.log(`
Verify independently (no server needed for the package):
  delil verify-export out/${contract.id}.zip --trusted-keys out/trusted-keys.json
  delil verify --stream ${stream} --trusted-keys out/trusted-keys.json --witness out/checkpoint.json`);
