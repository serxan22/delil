import "server-only";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { selectedProject, sessionToken } from "./session";

const API_URL = (process.env.DELIL_API_URL ?? "http://localhost:8080").replace(/\/+$/, "");

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

type Options = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  /** Send without the session (login). */
  anonymous?: boolean;
  /** Omit the Delil-Project header (tenant-level routes). */
  noProject?: boolean;
  /** Return the raw response (downloads). */
  raw?: boolean;
};

async function clientIp(): Promise<string | undefined> {
  const h = await headers();
  return h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? h.get("x-real-ip") ?? undefined;
}

/** Calls the DƏLİL API from the server. Redirects to /login on 401. */
export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const h: Record<string, string> = { Accept: "application/json" };
  if (!opts.anonymous) {
    const token = await sessionToken();
    if (!token) redirect("/login");
    h.Authorization = `Bearer ${token}`;
    if (!opts.noProject) {
      const project = await selectedProject();
      if (project) h["Delil-Project"] = project;
    }
  }
  if (opts.body !== undefined) h["Content-Type"] = "application/json";
  const ip = await clientIp();
  if (ip) h["X-Forwarded-For"] = ip;
  h["X-Delil-User-Agent"] = (await headers()).get("user-agent")?.slice(0, 300) ?? "";

  const res = await fetch(API_URL + path, {
    method: opts.method ?? "GET",
    headers: h,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    cache: "no-store",
  });
  if (opts.raw) {
    if (res.status === 401) redirect("/login");
    return res as unknown as T;
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    if (res.status === 401 && !opts.anonymous) redirect("/login");
    const e = data?.error ?? {};
    throw new ApiError(res.status, e.code ?? "http_error", e.message ?? res.statusText, e.requestId, e.details);
  }
  return data as T;
}

/** Turns an error into a message safe to show in the UI. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message + (err.requestId ? ` (request ${err.requestId})` : "");
  return "Something went wrong. Check that the DƏLİL API is reachable.";
}
