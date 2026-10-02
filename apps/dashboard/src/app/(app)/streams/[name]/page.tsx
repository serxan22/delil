import Link from "next/link";
import { notFound } from "next/navigation";
import { createCheckpoint, verifyStream } from "@/app/actions";
import { Hash, SubmitButton } from "@/components/client";
import { Icon } from "@/components/icons";
import { buttonClass, Card, CardHeader, EmptyState, Field, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { dateTime, num, short } from "@/lib/format";
import type { AuditEvent, Checkpoint, Page, Stream } from "@/lib/types";

export default async function StreamPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  let s: Stream;
  try {
    s = await api<Stream>(`/v1/streams/${encodeURIComponent(name)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  const [cps, events] = await Promise.all([
    api<Page<Checkpoint>>(`/v1/streams/${encodeURIComponent(name)}/checkpoints`),
    api<Page<AuditEvent>>(`/v1/events?stream=${encodeURIComponent(name)}&limit=10`),
  ]);
  return (
    <>
      <PageHeader
        title={s.name}
        description="Hash chain head, signed checkpoints and recent events."
        actions={
          <>
            <form action={createCheckpoint}><input type="hidden" name="stream" value={s.name} />
              <SubmitButton className={buttonClass.secondary}>Create checkpoint</SubmitButton></form>
            <form action={verifyStream}><input type="hidden" name="stream" value={s.name} />
              <SubmitButton className={buttonClass.primary} pendingText="Verifying…"><Icon name="verify" />Verify stream</SubmitButton></form>
          </>
        }
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Chain head" />
          <Field label="Events">{num(s.headSequence)}</Field>
          <Field label="Head hash"><Hash value={s.headHash} /></Field>
          <Field label="Last event">{dateTime(s.lastEventAt)}</Field>
          <Field label="Created">{dateTime(s.createdAt)}</Field>
          <Field label="Verification">
            <StatusBadge status={s.verification.status} />
            {s.verification.runId && <Link href={`/verification/${s.verification.runId}`} className="ml-2 text-sm text-muted hover:text-ink">report →</Link>}
          </Field>
        </Card>
        <Card>
          <CardHeader title="Checkpoints" description="Signed statements of the head. Save one with `delil checkpoints save` as an external witness." />
          {cps.data.length === 0 ? <EmptyState title="No checkpoints yet" /> : (
            <Table head={["Sequence", "Created", "Head hash"]}>
              {[...cps.data].reverse().slice(0, 8).map((c) => (
                <tr key={c.checkpointId}>
                  <Td className="tabular">#{num(c.sequence)}</Td>
                  <Td className="text-ink-2">{dateTime(c.createdAt)}</Td>
                  <Td mono className="text-ink-2">{short(c.headHash, 20)}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
      <Card className="mt-6">
        <CardHeader title="Recent events" action={<Link href={`/events?stream=${s.name}`} className="text-sm text-muted hover:text-ink">All →</Link>} />
        <Table head={["#", "Action", "Actor", "Recorded", "Event hash"]}>
          {events.data.map((e) => (
            <tr key={e.id} className="hover:bg-canvas/60">
              <Td className="tabular text-ink-2">{e.sequence}</Td>
              <Td><Link href={`/events/${e.id}`} className="font-medium hover:underline">{e.action}</Link></Td>
              <Td className="text-ink-2">{e.actor.displayName ?? e.actor.id}</Td>
              <Td className="text-ink-2">{dateTime(e.recordedAt)}</Td>
              <Td mono className="text-ink-2">{short(e.integrity.eventHash, 16)}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
