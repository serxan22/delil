import {
  DelilApiError,
  DelilError,
  DelilNetworkError,
  DelilTimeoutError,
  apiError,
  type ApiErrorBody,
} from "./errors.js";
import type {
  ApiKey,
  ApiKeyScope,
  AuditEvent,
  Checkpoint,
  CreateExportParams,
  EventInput,
  EventReceipt,
  Export,
  ListEventsParams,
  Page,
  PublicKey,
  SigningKey,
  Stream,
  VerificationReport,
  VerificationRun,
} from "./types.js";

export const VERSION = "0.1.0";

export interface DelilOptions {
  /** Base URL of the DƏLİL API, e.g. "http://localhost:8080". */
  baseUrl: string;
  /** Project API key (dlk_...). Never ship it to browsers. */
  apiKey: string | undefined;
  /** Per-attempt timeout in milliseconds. Default 10 000. */
  timeoutMs?: number;
  /**
   * Retries for transient failures (network errors, 429, 502, 503, 504).
   * Only safe requests are retried: reads, and writes that carry an
   * idempotency key (event recording always does). Default 2.
   */
  maxRetries?: number;
  /** Custom fetch implementation (tests, proxies). */
  fetch?: typeof fetch;
  /** Extra headers sent with every request. */
  headers?: Record<string, string>;
}

export interface RequestOptions {
  /** Makes a write safe to retry; the server returns the original result. */
  idempotencyKey?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface InternalRequest {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  raw?: boolean;
}

const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

function toTime(v: string | Date | undefined): string | undefined {
  return v instanceof Date ? v.toISOString() : v;
}

// A linear scan: the equivalent regex /\/+$/ backtracks quadratically.
function trimTrailingSlashes(url: string): string {
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 47 /* "/" */) end--;
  return url.slice(0, end);
}

function randomKey(): string {
  return globalThis.crypto.randomUUID();
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(signal.reason);
    });
  });

export class Delil {
  readonly events: EventsResource;
  readonly streams: StreamsResource;
  readonly verification: VerificationResource;
  readonly exports: ExportsResource;
  readonly apiKeys: ApiKeysResource;
  readonly signingKeys: SigningKeysResource;

  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof fetch;
  private readonly headers: Record<string, string>;

  constructor(options: DelilOptions) {
    if (!options.baseUrl) throw new DelilError("baseUrl is required");
    if (!options.apiKey) throw new DelilError("apiKey is required (set DELIL_API_KEY)");
    if (typeof window !== "undefined" && typeof (globalThis as { document?: unknown }).document !== "undefined") {
      console.warn("[delil] The SDK is running in a browser. API keys must never be exposed to browsers.");
    }
    this.baseUrl = trimTrailingSlashes(options.baseUrl);
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxRetries = Math.max(0, options.maxRetries ?? 2);
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.headers = options.headers ?? {};
    this.events = new EventsResource(this);
    this.streams = new StreamsResource(this);
    this.verification = new VerificationResource(this);
    this.exports = new ExportsResource(this);
    this.apiKeys = new ApiKeysResource(this);
    this.signingKeys = new SigningKeysResource(this);
  }

  /** GET /health (no authentication required). */
  async health(options?: RequestOptions): Promise<{ status: string; version: string }> {
    return this.request({ method: "GET", path: "/health", ...options });
  }

  /** @internal */
  async request<T>(req: InternalRequest): Promise<T> {
    const res = await this.send(req);
    if (req.raw) return res as unknown as T;
    const text = await res.text();
    const value = text ? JSON.parse(text) : undefined;
    if (value && typeof value === "object" && !Array.isArray(value) && res.headers.get("Idempotent-Replayed") !== null) {
      (value as Record<string, unknown>).replayed = res.headers.get("Idempotent-Replayed") === "true";
    }
    return value as T;
  }

  private async send(req: InternalRequest): Promise<Response> {
    const url = new URL(this.baseUrl + req.path);
    for (const [k, v] of Object.entries(req.query ?? {})) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = {
      ...this.headers,
      Accept: "application/json",
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": `delil-sdk-typescript/${VERSION}`,
    };
    if (req.body !== undefined) headers["Content-Type"] = "application/json";
    if (req.idempotencyKey) headers["Idempotency-Key"] = req.idempotencyKey;
    const safe = req.method === "GET" || Boolean(req.idempotencyKey);
    const attempts = safe ? this.maxRetries + 1 : 1;

    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt++) {
      const timeout = AbortSignal.timeout(req.timeoutMs ?? this.timeoutMs);
      const signal = req.signal ? AbortSignal.any([req.signal, timeout]) : timeout;
      let res: Response;
      try {
        res = await this.fetchImpl(url, {
          method: req.method,
          headers,
          body: req.body === undefined ? undefined : JSON.stringify(req.body),
          signal,
        });
      } catch (err) {
        if (req.signal?.aborted) throw err;
        lastError = timeout.aborted
          ? new DelilTimeoutError(`request timed out after ${req.timeoutMs ?? this.timeoutMs} ms`, { cause: err })
          : new DelilNetworkError(`could not reach ${this.baseUrl}`, { cause: err });
        if (attempt + 1 < attempts) {
          await sleep(backoff(attempt), req.signal);
          continue;
        }
        throw lastError;
      }
      if (res.ok) return res;
      const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
      const body = await readErrorBody(res);
      lastError = apiError(res.status, body, retryAfter);
      if (RETRYABLE_STATUS.has(res.status) && attempt + 1 < attempts) {
        await sleep(retryAfter ?? backoff(attempt), req.signal);
        continue;
      }
      throw lastError;
    }
    throw lastError instanceof Error ? lastError : new DelilError("request failed");
  }
}

function backoff(attempt: number): number {
  const base = 250 * 2 ** attempt;
  return base / 2 + Math.random() * base;
}

function parseRetryAfter(v: string | null): number | undefined {
  if (!v) return undefined;
  const secs = Number(v);
  return Number.isFinite(secs) ? Math.min(secs * 1000, 60_000) : undefined;
}

async function readErrorBody(res: Response): Promise<ApiErrorBody> {
  const text = await res.text().catch(() => "");
  try {
    const parsed = JSON.parse(text) as { error?: ApiErrorBody };
    if (parsed.error?.code) return parsed.error;
  } catch {
    // fall through
  }
  return { code: "http_error", message: text.slice(0, 500) || res.statusText, requestId: res.headers.get("X-Request-Id") ?? undefined };
}

class EventsResource {
  constructor(private readonly c: Delil) {}

  /**
   * Records one event. An idempotency key is generated when none is given,
   * so automatic retries can never create duplicates.
   */
  async record(event: EventInput, options: RequestOptions = {}): Promise<EventReceipt> {
    const receipt = await this.c.request<EventReceipt>({
      method: "POST",
      path: "/v1/events",
      body: { ...event, occurredAt: toTime(event.occurredAt) },
      ...options,
      idempotencyKey: options.idempotencyKey ?? randomKey(),
    });
    receipt.replayed = receipt.replayed === true;
    return receipt;
  }

  /** Records up to the server's batch limit atomically: all events or none. */
  async recordBatch(events: EventInput[], options: RequestOptions = {}): Promise<EventReceipt[]> {
    const page = await this.c.request<Page<EventReceipt> & { replayed?: boolean }>({
      method: "POST",
      path: "/v1/events/batch",
      body: { events: events.map((e) => ({ ...e, occurredAt: toTime(e.occurredAt) })) },
      ...options,
      idempotencyKey: options.idempotencyKey ?? randomKey(),
    });
    // Idempotent-Replayed describes the whole response; copy it to each receipt.
    const replayed = page.replayed === true;
    return page.data.map((r) => ({ ...r, replayed }));
  }

  get(id: string, options?: RequestOptions): Promise<AuditEvent> {
    return this.c.request({ method: "GET", path: `/v1/events/${encodeURIComponent(id)}`, ...options });
  }

  list(params: ListEventsParams = {}, options?: RequestOptions): Promise<Page<AuditEvent>> {
    return this.c.request({
      method: "GET",
      path: "/v1/events",
      query: { ...params, from: toTime(params.from), to: toTime(params.to) },
      ...options,
    });
  }

  /** Iterates over every matching event, following pagination. */
  async *iterate(params: ListEventsParams = {}, options?: RequestOptions): AsyncGenerator<AuditEvent> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor }, options);
      yield* page.data;
      cursor = page.hasMore ? page.nextCursor : undefined;
    } while (cursor);
  }

  /** Server-side verification of one event and its links to its neighbours. */
  verify(id: string, options?: RequestOptions): Promise<VerificationReport> {
    return this.c.request({ method: "GET", path: `/v1/events/${encodeURIComponent(id)}/verify`, ...options });
  }
}

class StreamsResource {
  constructor(private readonly c: Delil) {}

  async list(options?: RequestOptions): Promise<Stream[]> {
    return (await this.c.request<Page<Stream>>({ method: "GET", path: "/v1/streams", ...options })).data;
  }

  get(name: string, options?: RequestOptions): Promise<Stream> {
    return this.c.request({ method: "GET", path: `/v1/streams/${encodeURIComponent(name)}`, ...options });
  }

  /**
   * Asks the server to verify the stream. For verification that does not
   * trust the server, use the delil CLI (`delil verify --trusted-keys`).
   */
  verify(name: string, options?: RequestOptions): Promise<VerificationRun> {
    return this.c.request({ method: "POST", path: `/v1/streams/${encodeURIComponent(name)}/verify`, ...options });
  }

  async checkpoints(name: string, options?: RequestOptions): Promise<Checkpoint[]> {
    return (
      await this.c.request<Page<Checkpoint>>({
        method: "GET",
        path: `/v1/streams/${encodeURIComponent(name)}/checkpoints`,
        ...options,
      })
    ).data;
  }

  /** Signs the current head. Save the result outside DƏLİL as a witness. */
  createCheckpoint(name: string, options?: RequestOptions): Promise<Checkpoint> {
    return this.c.request({ method: "POST", path: `/v1/streams/${encodeURIComponent(name)}/checkpoints`, ...options });
  }
}

class VerificationResource {
  constructor(private readonly c: Delil) {}

  /** Verifies every stream of the project on the server. */
  project(options?: RequestOptions): Promise<VerificationRun> {
    return this.c.request({ method: "POST", path: "/v1/verify", ...options });
  }

  async runs(limit = 50, options?: RequestOptions): Promise<VerificationRun[]> {
    return (await this.c.request<Page<VerificationRun>>({ method: "GET", path: "/v1/verification-runs", query: { limit }, ...options }))
      .data;
  }

  run(id: string, options?: RequestOptions): Promise<VerificationRun> {
    return this.c.request({ method: "GET", path: `/v1/verification-runs/${encodeURIComponent(id)}`, ...options });
  }
}

class ExportsResource {
  constructor(private readonly c: Delil) {}

  /** Queues an evidence package. Poll with `get` or use `waitUntilReady`. */
  create(params: CreateExportParams, options?: RequestOptions): Promise<Export> {
    return this.c.request({
      method: "POST",
      path: "/v1/exports",
      body: { ...params, from: toTime(params.from), to: toTime(params.to) },
      ...options,
    });
  }

  get(id: string, options?: RequestOptions): Promise<Export> {
    return this.c.request({ method: "GET", path: `/v1/exports/${encodeURIComponent(id)}`, ...options });
  }

  async list(options?: RequestOptions): Promise<Export[]> {
    return (await this.c.request<Page<Export>>({ method: "GET", path: "/v1/exports", ...options })).data;
  }

  async waitUntilReady(id: string, { intervalMs = 1000, timeoutMs = 300_000 } = {}): Promise<Export> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const x = await this.get(id);
      if (x.status === "completed") return x;
      if (x.status === "failed" || x.status === "expired") {
        throw new DelilError(`export ${id} ${x.status}: ${x.error ?? "unknown error"}`);
      }
      if (Date.now() > deadline) throw new DelilTimeoutError(`export ${id} not ready after ${timeoutMs} ms`);
      await sleep(intervalMs);
    }
  }

  /** Downloads the ZIP package. Verify it offline with `delil verify-export`. */
  async download(id: string, options?: RequestOptions): Promise<Uint8Array> {
    const res = await this.c.request<Response>({
      method: "GET",
      path: `/v1/exports/${encodeURIComponent(id)}/download`,
      raw: true,
      ...options,
    });
    return new Uint8Array(await res.arrayBuffer());
  }
}

class ApiKeysResource {
  constructor(private readonly c: Delil) {}

  /** Creates a key. The returned `secret` is shown exactly once. */
  create(params: { name: string; scopes: ApiKeyScope[]; expiresAt?: string | Date }, options?: RequestOptions): Promise<ApiKey> {
    return this.c.request({ method: "POST", path: "/v1/api-keys", body: { ...params, expiresAt: toTime(params.expiresAt) }, ...options });
  }

  async list(options?: RequestOptions): Promise<ApiKey[]> {
    return (await this.c.request<Page<ApiKey>>({ method: "GET", path: "/v1/api-keys", ...options })).data;
  }

  revoke(id: string, options?: RequestOptions): Promise<ApiKey> {
    return this.c.request({ method: "DELETE", path: `/v1/api-keys/${encodeURIComponent(id)}`, ...options });
  }
}

class SigningKeysResource {
  constructor(private readonly c: Delil) {}

  async list(options?: RequestOptions): Promise<SigningKey[]> {
    return (await this.c.request<Page<SigningKey>>({ method: "GET", path: "/v1/signing-keys", ...options })).data;
  }

  /** Public keys in the trusted-keys format used for pinning. */
  async export(options?: RequestOptions): Promise<{ keys: PublicKey[] }> {
    return this.c.request({ method: "GET", path: "/v1/signing-keys/export", ...options });
  }

  rotate(options?: RequestOptions): Promise<{ previous: SigningKey; current: SigningKey }> {
    return this.c.request({ method: "POST", path: "/v1/signing-keys/rotate", ...options });
  }
}

export { DelilApiError };
