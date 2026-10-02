import Link from "next/link";
import { notFound } from "next/navigation";
import { Hash } from "@/components/client";
import { DiffTable, JsonBlock } from "@/components/json";
import { Card, CardHeader, Field, PageHeader, StatusBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { AuditEvent } from "@/lib/types";
import { VerifyEvent } from "./verify";

export const metadata = { title: "Event" };

export default async function EventPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let e: AuditEvent;
  try {
    e = await api<AuditEvent>(`/v1/events/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  return (
    <>
      <PageHeader
        title={e.action}
        description={<>Event <span className="font-mono">{e.id}</span> · {e.stream} #{e.sequence}</>}
        actions={<StatusBadge status={e.verification?.status} />}
      />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <Card>
            <CardHeader title="Event" />
            <Field label="Actor">{e.actor.displayName ?? e.actor.id} <span className="font-mono text-[12px] text-muted">({e.actor.type}:{e.actor.id})</span></Field>
            <Field label="Action">{e.action}</Field>
            <Field label="Resource">{e.resource ? <span className="font-mono text-[13px]">{e.resource.type}:{e.resource.id}</span> : "—"}{e.resource?.displayName && <span className="text-muted"> · {e.resource.displayName}</span>}</Field>
            <Field label="Stream">
              <Link href={`/streams/${e.stream}`} className="hover:underline">{e.stream}</Link> · sequence {e.sequence}
            </Field>
            <Field label="Occurred at">{e.occurredAt ? <>{dateTime(e.occurredAt)} <span className="text-muted">(asserted by the application)</span></> : "—"}</Field>
            <Field label="Recorded at">{dateTime(e.recordedAt)} <span className="text-muted">(server clock)</span></Field>
            {e.context && (
              <Field label="Request">
                <span className="font-mono text-[12.5px]">{[e.context.sourceIp, e.context.requestId, e.context.userAgent].filter(Boolean).join(" · ")}</span>
              </Field>
            )}
            {e.redactions && e.redactions.length > 0 && (
              <Field label="Redacted"><span className="font-mono text-[12.5px]">{e.redactions.join(", ")}</span> <span className="text-muted">(removed before storage)</span></Field>
            )}
          </Card>
          {e.changes && e.changes.length > 0 && (
            <Card><CardHeader title="Diff" description="Computed by DƏLİL from before and after" /><div className="p-5"><DiffTable changes={e.changes} /></div></Card>
          )}
          {e.before !== undefined && <Card><CardHeader title="Before" /><div className="p-5"><JsonBlock value={e.before} /></div></Card>}
          {e.after !== undefined && <Card><CardHeader title="After" /><div className="p-5"><JsonBlock value={e.after} /></div></Card>}
          {e.data !== undefined && <Card><CardHeader title="Data" /><div className="p-5"><JsonBlock value={e.data} /></div></Card>}
          {e.metadata !== undefined && <Card><CardHeader title="Metadata" /><div className="p-5"><JsonBlock value={e.metadata} /></div></Card>}
        </div>
        <div className="space-y-6 lg:col-span-2">
          <VerifyEvent id={e.id} />
          <Card>
            <CardHeader title="Integrity" description={`Schema v${e.integrity.schemaVersion} · ${e.integrity.algorithm}`} />
            <div className="space-y-4 p-5 text-sm">
              {([
                ["Event ID", e.id],
                ["Sequence", String(e.sequence)],
                ["Previous hash", e.integrity.previousHash],
                ["Payload hash", e.integrity.payloadHash],
                ["Event hash", e.integrity.eventHash],
                ["Signature", e.integrity.signature],
                ["Signing key", e.integrity.signingKeyId],
              ] as const).map(([label, value]) => (
                <div key={label}>
                  <div className="mb-0.5 text-[12px] text-muted">{label}</div>
                  <Hash value={value} />
                </div>
              ))}
              <div>
                <div className="mb-0.5 text-[12px] text-muted">Recorded timestamp</div>
                <Hash value={e.recordedAt} />
              </div>
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
