"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { api, ApiError, errorMessage } from "@/lib/api";
import { clearSession, setProject, setSession } from "@/lib/session";
import type { ApiKey, Export, Project, Report, Run, Session } from "@/lib/types";

export type FormState = { error?: string; ok?: string; secret?: string; report?: Report };

const str = (f: FormData, k: string) => String(f.get(k) ?? "").trim();

export async function login(_: FormState, form: FormData): Promise<FormState> {
  let session: Session;
  try {
    session = await api<Session>("/v1/auth/login", {
      method: "POST",
      anonymous: true,
      body: { email: str(form, "email"), password: String(form.get("password") ?? "") },
    });
  } catch (err) {
    if (err instanceof ApiError && (err.status === 401 || err.status === 429)) return { error: err.message };
    return { error: errorMessage(err) };
  }
  await setSession(session.token!, session.expiresAt);
  if (session.projects[0]) await setProject(session.projects[0].id);
  redirect("/");
}

export async function logout() {
  try {
    await api("/v1/auth/logout", { method: "POST", noProject: true });
  } catch {
    // The session may already be gone; clearing the cookie is what matters.
  }
  await clearSession();
  redirect("/login");
}

export async function switchProject(form: FormData) {
  const id = str(form, "projectId");
  const session = await api<Session>("/v1/auth/session", { noProject: true });
  if (session.projects.some((p) => p.id === id)) await setProject(id);
  redirect("/");
}

export async function verifyProject() {
  const run = await api<Run>("/v1/verify", { method: "POST" });
  redirect(`/verification/${run.id}`);
}

export async function verifyStream(form: FormData) {
  const run = await api<Run>(`/v1/streams/${encodeURIComponent(str(form, "stream"))}/verify`, { method: "POST" });
  redirect(`/verification/${run.id}`);
}

export async function verifyEvent(_: FormState, form: FormData): Promise<FormState> {
  try {
    return { report: await api<Report>(`/v1/events/${encodeURIComponent(str(form, "id"))}/verify`) };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

export async function createCheckpoint(form: FormData) {
  const stream = str(form, "stream");
  await api(`/v1/streams/${encodeURIComponent(stream)}/checkpoints`, { method: "POST" });
  revalidatePath(`/streams/${stream}`);
}

export async function createExport(_: FormState, form: FormData): Promise<FormState> {
  const body: Record<string, unknown> = { stream: str(form, "stream") };
  for (const k of ["from", "to", "actorId", "action", "resourceType", "resourceId"]) {
    const v = str(form, k);
    if (v) body[k] = v;
  }
  try {
    const x = await api<Export>("/v1/exports", { method: "POST", body });
    revalidatePath("/exports");
    return { ok: `Export ${x.id} queued. It appears below when ready.` };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

export async function createApiKey(_: FormState, form: FormData): Promise<FormState> {
  const scopes = form.getAll("scopes").map(String);
  try {
    const key = await api<ApiKey>("/v1/api-keys", { method: "POST", body: { name: str(form, "name"), scopes } });
    revalidatePath("/api-keys");
    return { secret: key.secret, ok: `Created “${key.name}”.` };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

export async function revokeApiKey(form: FormData) {
  await api(`/v1/api-keys/${encodeURIComponent(str(form, "id"))}`, { method: "DELETE" });
  revalidatePath("/api-keys");
}

export async function rotateSigningKey() {
  await api("/v1/signing-keys/rotate", { method: "POST" });
  revalidatePath("/signing-keys");
}

export async function createProject(_: FormState, form: FormData): Promise<FormState> {
  try {
    const p = await api<Project>("/v1/projects", { method: "POST", noProject: true, body: { name: str(form, "name") } });
    revalidatePath("/projects");
    return { ok: `Created project ${p.name}.` };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

export async function updateSettings(_: FormState, form: FormData): Promise<FormState> {
  const list = (k: string) => str(form, k).split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  const settings = {
    retainStates: str(form, "retainStates") || "full",
    redaction: { mode: str(form, "mode") || "redact", keys: list("keys"), paths: list("paths"), disableDefaults: form.get("disableDefaults") === "on" },
  };
  try {
    await api("/v1/project", { method: "PATCH", body: { settings } });
    revalidatePath("/settings");
    return { ok: "Settings saved. They apply to events recorded from now on." };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

export async function changePassword(_: FormState, form: FormData): Promise<FormState> {
  try {
    await api("/v1/auth/password", {
      method: "POST",
      noProject: true,
      body: { currentPassword: String(form.get("currentPassword") ?? ""), newPassword: String(form.get("newPassword") ?? "") },
    });
    return { ok: "Password changed. Other sessions were signed out." };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}
