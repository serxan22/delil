import Link from "next/link";
import { buttonClass, Card, EmptyState, inputClass, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { AuditEvent, Page, Stream } from "@/lib/types";

export const metadata = { title: "Events" };

const FILTERS = ["stream", "actorId", "action", "resourceType", "resourceId", "from", "to", "verificationStatus"] as const;

export default async function EventsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const q = new URLSearchParams();
  for (const k of [...FILTERS, "cursor"]) if (sp[k]) q.set(k, sp[k]!);
  q.set("limit", "50");
  const [page, streams] = await Promise.all([
    api<Page<AuditEvent>>(`/v1/events?${q}`),
    api<Page<Stream>>("/v1/streams"),
  ]);
  const next = new URLSearchParams(q);
  if (page.nextCursor) next.set("cursor", page.nextCursor);
  return (
    <>
      <PageHeader title="Events" description="Every audit event, newest first. Content is rendered from the signed record." />
      <Card className="mb-4 p-4">
        <form className="grid gap-3 md:grid-cols-4 lg:grid-cols-8" method="get">
          <select name="stream" defaultValue={sp.stream ?? ""} className={inputClass} aria-label="Stream">
            <option value="">All streams</option>
            {streams.data.map((s) => <option key={s.id} value={s.name}>{s.name}</option>)}
          </select>
          <input name="actorId" defaultValue={sp.actorId} placeholder="Actor id" className={inputClass} />
          <input name="action" defaultValue={sp.action} placeholder="Action (prefix*)" className={inputClass} />
          <input name="resourceType" defaultValue={sp.resourceType} placeholder="Resource type" className={inputClass} />
          <input name="resourceId" defaultValue={sp.resourceId} placeholder="Resource id" className={inputClass} />
          <input name="from" type="date" defaultValue={sp.from} className={inputClass} aria-label="From" />
          <input name="to" type="date" defaultValue={sp.to} className={inputClass} aria-label="To" />
          <div className="flex gap-2">
            <select name="verificationStatus" defaultValue={sp.verificationStatus ?? ""} className={inputClass} aria-label="Verification status">
              <option value="">Any status</option>
              <option value="verified">Verified</option>
              <option value="failed">Failed</option>
              <option value="unverified">Unverified</option>
            </select>
            <button className={buttonClass.secondary} type="submit">Filter</button>
          </div>
        </form>
      </Card>
      <Card>
        {page.data.length === 0 ? (
          <EmptyState title="No matching events" />
        ) : (
          <Table head={["Recorded (UTC)", "Stream", "Action", "Actor", "Resource", "Status"]}>
            {page.data.map((e) => (
              <tr key={e.id} className="hover:bg-canvas/60">
                <Td className="whitespace-nowrap text-ink-2 tabular">{dateTime(e.recordedAt).replace(" UTC", "")}</Td>
                <Td className="whitespace-nowrap">{e.stream} <span className="text-faint">#{e.sequence}</span></Td>
                <Td><Link href={`/events/${e.id}`} className="font-medium hover:underline">{e.action}</Link></Td>
                <Td className="text-ink-2">{e.actor.displayName ?? e.actor.id}<div className="font-mono text-[11.5px] text-faint">{e.actor.type}:{e.actor.id}</div></Td>
                <Td className="font-mono text-[12px] text-ink-2">{e.resource ? `${e.resource.type}:${e.resource.id}` : "—"}</Td>
                <Td><StatusBadge status={e.verification?.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
        <div className="flex justify-between border-t border-line px-5 py-3 text-sm">
          <Link href="/events" className="text-muted hover:text-ink">Reset filters</Link>
          {page.hasMore && <Link href={`/events?${next}`} className="font-medium hover:underline">Older events →</Link>}
        </div>
      </Card>
    </>
  );
}
