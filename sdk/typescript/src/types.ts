/** JSON value accepted in before/after/data/metadata. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface Actor {
  /** Kind of actor, e.g. "user", "service", "system". */
  type: string;
  /** Stable identifier of the actor in your system. Prefer pseudonymous ids over emails. */
  id: string;
  displayName?: string;
}

export interface Resource {
  type: string;
  id: string;
  displayName?: string;
}

export interface RequestContext {
  requestId?: string;
  traceId?: string;
  sessionId?: string;
  sourceIp?: string;
  userAgent?: string;
}

export interface EventInput {
  /** Stream name: ^[a-z0-9][a-z0-9._-]{0,63}$. Created on first use. */
  stream: string;
  actor: Actor;
  /** Dot-separated action, e.g. "contract.approved". */
  action: string;
  resource?: Resource;
  /** State before the change. `null` means the resource did not exist. */
  before?: JsonValue;
  /** State after the change. `null` means the resource no longer exists. */
  after?: JsonValue;
  /** Domain-specific payload when before/after do not fit. */
  data?: JsonValue;
  metadata?: { [key: string]: JsonValue };
  context?: RequestContext;
  /** When the action happened, as asserted by your application. */
  occurredAt?: string | Date;
}

export interface EventReceipt {
  object: "event_receipt";
  id: string;
  stream: string;
  sequence: number;
  recordedAt: string;
  eventHash: string;
  previousHash: string;
  payloadHash: string;
  signature: string;
  signingKeyId: string;
  /** "valid" means the server re-verified the signature and link before committing. */
  verificationStatus: "valid";
  /** True when the response replays an earlier request with the same idempotency key. */
  replayed: boolean;
}

export interface Change {
  op: "add" | "remove" | "replace";
  path: string;
  from?: JsonValue;
  to?: JsonValue;
}

export interface EventIntegrity {
  schemaVersion: number;
  previousHash: string;
  payloadHash: string;
  eventHash: string;
  signature: string;
  signingKeyId: string;
  algorithm: "Ed25519";
}

export interface AuditEvent {
  object: "event";
  id: string;
  stream: string;
  sequence: number;
  action: string;
  actor: Actor;
  resource?: Resource;
  before?: JsonValue;
  after?: JsonValue;
  changes?: Change[];
  data?: JsonValue;
  metadata?: { [key: string]: JsonValue };
  context?: RequestContext;
  occurredAt?: string;
  recordedAt: string;
  redactions?: string[];
  integrity: EventIntegrity;
  verification?: { status: "verified" | "failed" | "unverified"; verifiedAt?: string; runId?: string };
}

export interface Page<T> {
  object: "list";
  data: T[];
  hasMore: boolean;
  nextCursor?: string;
}

export interface ListEventsParams {
  stream?: string;
  actorId?: string;
  actorType?: string;
  /** Exact action, or a prefix ending with "*". */
  action?: string;
  resourceType?: string;
  resourceId?: string;
  from?: string | Date;
  to?: string | Date;
  verificationStatus?: "verified" | "failed" | "unverified";
  limit?: number;
  cursor?: string;
}

export interface Stream {
  object: "stream";
  id: string;
  name: string;
  headSequence: number;
  headHash: string;
  lastEventAt?: string;
  lastCheckpointSequence: number;
  createdAt: string;
  verification: {
    status: "passed" | "failed" | "never";
    verifiedAt?: string;
    runId?: string;
    lastSequence?: number;
    failureCount: number;
    firstFailureSequence?: number;
  };
}

export type CheckStatus = "valid" | "invalid" | "skipped";

export interface VerificationFailure {
  code: string;
  check: string;
  severity: "error" | "warning";
  sequence?: number;
  eventId?: string;
  message: string;
  expected?: string;
  found?: string;
}

export interface VerificationReport {
  object: "verification_report";
  scope: "stream" | "event" | "evidence_package";
  result: "valid" | "invalid";
  valid: boolean;
  tamperingDetected: boolean;
  stream?: string;
  eventId?: string;
  eventsChecked: number;
  payloadsChecked: number;
  firstSequence?: number;
  lastSequence?: number;
  lastEventHash?: string;
  checks: {
    hashChain: CheckStatus;
    payloadHashes: CheckStatus;
    signatures: CheckStatus;
    ordering: CheckStatus;
    checkpoints: CheckStatus;
    streamHead: CheckStatus;
  };
  checkpointsVerified: number;
  keysUsed: string[];
  firstFailure: VerificationFailure | null;
  failures: VerificationFailure[];
  failureCount: number;
  failuresTruncated: boolean;
  warnings: VerificationFailure[];
  startedAt: string;
  completedAt: string;
  durationMs: number;
}

export interface VerificationRun {
  object: "verification_run";
  id: string;
  scope: "event" | "stream" | "project";
  target?: string;
  status: "running" | "passed" | "failed" | "error";
  trigger: string;
  triggeredBy?: string;
  streamsChecked: number;
  eventsChecked: number;
  failureCount: number;
  startedAt: string;
  completedAt?: string;
  report?: unknown;
}

export interface Checkpoint {
  object?: "checkpoint";
  schemaVersion: number;
  checkpointId: string;
  tenantId: string;
  projectId: string;
  stream: string;
  sequence: number;
  headHash: string;
  createdAt: string;
  keyId: string;
  checkpointHash: string;
  signature: string;
}

export interface CreateExportParams {
  stream: string;
  /** Recorded at or after (RFC 3339 or YYYY-MM-DD). */
  from?: string | Date;
  /** Recorded before (RFC 3339 or YYYY-MM-DD). */
  to?: string | Date;
  fromSequence?: number;
  toSequence?: number;
  /** Disclosure filters: only matching events reveal their content. */
  actorId?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
}

export interface Export {
  object: "export";
  id: string;
  stream: string;
  status: "pending" | "running" | "completed" | "failed" | "expired";
  createdAt: string;
  completedAt?: string;
  expiresAt?: string;
  chainEvents?: number;
  disclosedEvents?: number;
  firstSequence?: number;
  lastSequence?: number;
  sizeBytes?: number;
  sha256?: string;
  manifestHash?: string;
  verificationValid?: boolean;
  error?: string;
  downloadUrl?: string;
}

export type ApiKeyScope =
  | "events:write"
  | "events:read"
  | "verify"
  | "exports"
  | "keys:read"
  | "keys:rotate"
  | "api_keys:manage";

export interface ApiKey {
  object: "api_key";
  id: string;
  name: string;
  prefix: string;
  scopes: ApiKeyScope[];
  createdAt: string;
  lastUsedAt?: string;
  expiresAt?: string;
  revokedAt?: string;
  /** Only present when the key is created. Store it securely; it is never shown again. */
  secret?: string;
}

export interface SigningKey {
  object: "signing_key";
  id: string;
  algorithm: "Ed25519";
  publicKey: string;
  fingerprint: string;
  status: "active" | "retired" | "revoked";
  provider: string;
  createdAt: string;
  activatedAt: string;
  retiredAt?: string;
  revokedAt?: string;
  revocationReason?: string;
  eventsSigned: number;
}

export interface PublicKey {
  keyId: string;
  algorithm: "Ed25519";
  publicKey: string;
  fingerprint: string;
  projectId?: string;
  status?: string;
  activatedAt?: string;
  retiredAt?: string;
  revokedAt?: string;
}
