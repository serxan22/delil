import Link from "next/link";
import { verifyStream } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { buttonClass, Card, EmptyState, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { num, relative, short } from "@/lib/format";
import type { Page, Stream } from "@/lib/types";

export const metadata = { title: "Streams" };

export default async function StreamsPage() {
  const { data } = await api<Page<Stream>>("/v1/streams");
  return (
    <>
      <PageHeader title="Streams" description="Each stream is an independent hash chain. Streams are created on their first event." />
      <Card>
        {data.length === 0 ? <EmptyState title="No streams yet" /> : (
          <Table head={["Stream", "Events", "Head hash", "Last event", "Checkpoint", "Verification", ""]}>
            {data.map((s) => (
              <tr key={s.id} className="hover:bg-canvas/60">
                <Td><Link href={`/streams/${s.name}`} className="font-medium hover:underline">{s.name}</Link></Td>
                <Td className="tabular">{num(s.headSequence)}</Td>
                <Td mono className="text-ink-2">{short(s.headHash, 16)}</Td>
                <Td className="text-ink-2">{relative(s.lastEventAt)}</Td>
                <Td className="tabular text-ink-2">#{num(s.lastCheckpointSequence)}</Td>
                <Td>
                  <StatusBadge status={s.verification.status} />
                  {s.verification.verifiedAt && <div className="mt-1 text-[12px] text-muted">{relative(s.verification.verifiedAt)}{s.verification.lastSequence !== undefined && s.verification.lastSequence < s.headSequence ? ` · ${s.headSequence - s.verification.lastSequence} newer` : ""}</div>}
                </Td>
                <Td className="text-right">
                  <form action={verifyStream}>
                    <input type="hidden" name="stream" value={s.name} />
                    <SubmitButton className={buttonClass.secondary} pendingText="Verifying…">Verify</SubmitButton>
                  </form>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
