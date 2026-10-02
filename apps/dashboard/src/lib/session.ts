import "server-only";
import { cookies } from "next/headers";

// The session token lives only in an HTTP-only cookie on the dashboard's own
// origin. Browser JavaScript never sees it; the Next.js server forwards it to
// the API as a bearer token.
const secure = process.env.DELIL_COOKIE_SECURE !== "false" && process.env.NODE_ENV === "production";
export const SESSION_COOKIE = secure ? "__Host-delil_session" : "delil_session";
export const PROJECT_COOKIE = "delil_project";

export async function sessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}

export async function selectedProject(): Promise<string | undefined> {
  return (await cookies()).get(PROJECT_COOKIE)?.value;
}

export async function setSession(token: string, expiresAt: string) {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    expires: new Date(expiresAt),
  });
}

export async function setProject(projectId: string) {
  (await cookies()).set(PROJECT_COOKIE, projectId, { httpOnly: true, secure, sameSite: "lax", path: "/" });
}

export async function clearSession() {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
  jar.delete(PROJECT_COOKIE);
}
