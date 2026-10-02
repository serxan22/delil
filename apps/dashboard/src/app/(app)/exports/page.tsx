import { Card, CardHeader, EmptyState, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { bytes, dateTime, num } from "@/lib/format";
import type { Export, Page, Stream } from "@/lib/types";
import { ExportForm } from "./form";

export const metadata = { title: "Evidence exports" };

export default async function ExportsPage() {
  const [exports, streams] = await Promise.all([api<Page<Export>>("/v1/exports"), api<Page<Stream>>("/v1/streams")]);
  return (
    <>
      <PageHeader
        title="Evidence exports"
        description="Signed, self-contained packages that anyone can verify offline with `delil verify-export`, without access to this server."
      />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader title="New export" description="Select a stream and an optional time window. Filters limit which events disclose their content; the chain stays verifiable." />
          <ExportForm streams={streams.data.map((s) => s.name)} />
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Packages" />
          {exports.data.length === 0 ? <EmptyState title="No exports yet" /> : (
            <Table head={["Export", "Stream", "Status", "Events", "Size", "Created", ""]}>
              {exports.data.map((x) => (
                <tr key={x.id}>
                  <Td mono className="text-[12px]">{x.id}</Td>
                  <Td>{x.stream}</Td>
                  <Td><StatusBadge status={x.status} />{x.error && <div className="mt-1 max-w-48 text-[12px] text-bad">{x.error}</div>}</Td>
                  <Td className="tabular">{x.disclosedEvents !== undefined ? `${num(x.disclosedEvents)} / ${num(x.chainEvents)}` : "—"}</Td>
                  <Td className="tabular text-ink-2">{bytes(x.sizeBytes)}</Td>
                  <Td className="whitespace-nowrap text-ink-2">{dateTime(x.createdAt)}</Td>
                  <Td>{x.status === "completed" && <a href={`/exports/${x.id}/download`} className="font-medium text-accent hover:underline">Download</a>}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
