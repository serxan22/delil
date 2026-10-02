import { api } from "@/lib/api";

const ID = /^exp_[0-9A-Z]{26}$/;

// Streams the package from the API through the dashboard, authenticated with
// the user's session. GET has no side effects.
export async function GET(_: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!ID.test(id)) return new Response("not found", { status: 404 });
  const res = await api<Response>(`/v1/exports/${id}/download`, { raw: true });
  if (!res.ok) return new Response("export not available", { status: res.status });
  return new Response(res.body, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": res.headers.get("Content-Disposition") ?? `attachment; filename="${id}.zip"`,
      "Cache-Control": "no-store",
    },
  });
}
