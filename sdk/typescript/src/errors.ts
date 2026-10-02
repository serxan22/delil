/** Base class of every error thrown by the SDK. */
export class DelilError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

export interface ApiErrorBody {
  code: string;
  message: string;
  requestId?: string;
  details?: unknown;
}

/** The API answered with an error status. */
export class DelilApiError extends DelilError {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | undefined;
  readonly details: unknown;

  constructor(status: number, body: ApiErrorBody) {
    super(`${body.code}: ${body.message}${body.requestId ? ` (request ${body.requestId})` : ""}`);
    this.status = status;
    this.code = body.code;
    this.requestId = body.requestId;
    this.details = body.details;
  }
}

/** 400/422: the request or event failed validation. `details.errors` lists fields. */
export class DelilValidationError extends DelilApiError {}
/** 401: missing, invalid, expired or revoked credentials. */
export class DelilAuthenticationError extends DelilApiError {}
/** 403: the API key lacks the required scope. */
export class DelilPermissionError extends DelilApiError {}
/** 404: the resource does not exist (or belongs to another tenant). */
export class DelilNotFoundError extends DelilApiError {}
/** 409: conflict, e.g. an export that is not ready. */
export class DelilConflictError extends DelilApiError {}

/** 429: rate limited. `retryAfterMs` is the server's hint. */
export class DelilRateLimitError extends DelilApiError {
  readonly retryAfterMs: number | undefined;
  constructor(status: number, body: ApiErrorBody, retryAfterMs: number | undefined) {
    super(status, body);
    this.retryAfterMs = retryAfterMs;
  }
}

/** The request did not complete within the configured timeout. */
export class DelilTimeoutError extends DelilError {}

/** The server could not be reached. */
export class DelilNetworkError extends DelilError {}

export function apiError(status: number, body: ApiErrorBody, retryAfterMs?: number): DelilApiError {
  switch (true) {
    case status === 400 || status === 413 || status === 415 || status === 422:
      return new DelilValidationError(status, body);
    case status === 401:
      return new DelilAuthenticationError(status, body);
    case status === 403:
      return new DelilPermissionError(status, body);
    case status === 404:
      return new DelilNotFoundError(status, body);
    case status === 409:
      return new DelilConflictError(status, body);
    case status === 429:
      return new DelilRateLimitError(status, body, retryAfterMs);
    default:
      return new DelilApiError(status, body);
  }
}
