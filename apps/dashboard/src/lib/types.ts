export type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

export interface Page<T> { data: T[]; hasMore: boolean; nextCursor?: string }

export interface Project { id: string; slug: string; name: string; createdAt: string; settings?: ProjectSettings; tenant?: { id: string; name: string; slug: string } }
export interface ProjectSettings {
  retainStates: "full" | "diff";
  maxEventBytes?: number;
  redaction: { keys: string[]; paths: string[]; mode: "redact" | "remove" | "mask"; disableDefaults: boolean };
}
export interface User { id: string; email: string; displayName: string; role: "admin" | "auditor" | "viewer"; createdAt: string; lastLoginAt?: string }
export interface Session { user: User; tenant: { id: string; name: string; slug: string }; projects: Project[]; expiresAt: string; token?: string }

export interface Change { op: "add" | "remove" | "replace"; path: string; from?: Json; to?: Json }
export interface AuditEvent {
  id: string; stream: string; sequence: number; action: string;
  actor: { type: string; id: string; displayName?: string };
  resource?: { type: string; id: string; displayName?: string };
  before?: Json; after?: Json; changes?: Change[]; data?: Json; metadata?: Json;
  context?: { requestId?: string; traceId?: string; sessionId?: string; sourceIp?: string; userAgent?: string };
  occurredAt?: string; recordedAt: string; redactions?: string[];
  integrity: { schemaVersion: number; previousHash: string; payloadHash: string; eventHash: string; signature: string; signingKeyId: string; algorithm: string };
  verification?: { status: "verified" | "failed" | "unverified"; verifiedAt?: string; runId?: string };
}

export interface Stream {
  id: string; name: string; headSequence: number; headHash: string; lastEventAt?: string; lastCheckpointSequence: number; createdAt: string;
  verification: { status: "passed" | "failed" | "never"; verifiedAt?: string; runId?: string; lastSequence?: number; failureCount: number; firstFailureSequence?: number };
}

export type CheckStatus = "valid" | "invalid" | "skipped";
export interface Failure { code: string; check: string; severity: string; sequence?: number; eventId?: string; message: string; expected?: string; found?: string }
export interface Report {
  scope: string; valid: boolean; tamperingDetected: boolean; stream?: string; eventId?: string;
  eventsChecked: number; payloadsChecked: number; firstSequence?: number; lastSequence?: number; anchor?: string;
  checks: Record<"hashChain" | "payloadHashes" | "signatures" | "ordering" | "checkpoints" | "streamHead", CheckStatus>;
  checkpointsVerified: number; keysUsed: string[]; keySource?: string;
  firstFailure: Failure | null; failures: Failure[]; failureCount: number; failuresTruncated: boolean; warnings: Failure[];
  startedAt: string; completedAt: string; durationMs: number;
}
export interface ProjectReport { valid: boolean; streamsChecked: number; eventsChecked: number; failureCount: number; streams: Report[] }
export interface Run {
  id: string; scope: "event" | "stream" | "project"; target?: string; status: "running" | "passed" | "failed" | "error";
  trigger: string; triggeredBy?: string; streamsChecked: number; eventsChecked: number; failureCount: number;
  startedAt: string; completedAt?: string; report?: Report | ProjectReport;
}
export interface Checkpoint { checkpointId: string; stream: string; sequence: number; headHash: string; createdAt: string; keyId: string; checkpointHash: string; signature: string }
export interface Export {
  id: string; stream: string; status: "pending" | "running" | "completed" | "failed" | "expired";
  params: Record<string, unknown>; createdBy?: string; createdAt: string; completedAt?: string; expiresAt?: string;
  chainEvents?: number; disclosedEvents?: number; firstSequence?: number; lastSequence?: number; sizeBytes?: number;
  sha256?: string; manifestHash?: string; verificationValid?: boolean; error?: string;
}
export interface ApiKey { id: string; name: string; prefix: string; scopes: string[]; createdBy?: string; createdAt: string; lastUsedAt?: string; expiresAt?: string; revokedAt?: string; secret?: string }
export interface SigningKey { id: string; algorithm: string; publicKey: string; fingerprint: string; status: "active" | "retired" | "revoked"; provider: string; createdAt: string; activatedAt: string; retiredAt?: string; revokedAt?: string; revocationReason?: string; eventsSigned: number }
export interface Overview {
  project: Project;
  stats: { eventsTotal: number; eventsToday: number; streams: number; activeStreams: number; lastEventAt?: string };
  verification: { status: "healthy" | "failing" | "unverified"; streamsPassing: number; streamsFailing: number; streamsUnverified: number; latestRun?: Run };
  eventsPerDay: { date: string; count: number }[];
  recentEvents: AuditEvent[];
  signingKey?: SigningKey;
}
