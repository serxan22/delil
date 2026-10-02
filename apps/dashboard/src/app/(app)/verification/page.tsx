import Link from "next/link";
import { verifyProject } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { Icon } from "@/components/icons";
import { buttonClass, Card, EmptyState, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime, num } from "@/lib/format";
import type { Page, Run } from "@/lib/types";

export const metadata = { title: "Verification" };

export default async function VerificationPage() {
  const { data } = await api<Page<Run>>("/v1/verification-runs?limit=100");
  return (
    <>
      <PageHeader
        title="Verification"
        description={<>Every run recomputes payload hashes, event hashes, chain links, sequence continuity and Ed25519 signatures from the stored records. To verify without trusting this server, run <code className="font-mono text-[13px]">delil verify --trusted-keys</code>.</>}
        actions={<form action={verifyProject}><SubmitButton className={buttonClass.primary} pendingText="Verifying…"><Icon name="verify" />Verify all streams</SubmitButton></form>}
      />
      <Card>
        {data.length === 0 ? <EmptyState title="No verification runs yet" /> : (
          <Table head={["Run", "Scope", "Result", "Events", "Failures", "Trigger", "Completed"]}>
            {data.map((r) => (
              <tr key={r.id} className="hover:bg-canvas/60">
                <Td mono><Link href={`/verification/${r.id}`} className="hover:underline">{r.id}</Link></Td>
                <Td>{r.scope}{r.target && <span className="text-muted"> · {r.target}</span>}</Td>
                <Td><StatusBadge status={r.status} /></Td>
                <Td className="tabular">{num(r.eventsChecked)}</Td>
                <Td className={`tabular ${r.failureCount ? "font-semibold text-bad" : ""}`}>{num(r.failureCount)}</Td>
                <Td className="text-ink-2">{r.trigger}</Td>
                <Td className="whitespace-nowrap text-ink-2">{dateTime(r.completedAt)}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
