import { notFound } from "next/navigation";
import { ReportView } from "@/components/report";
import { Card, PageHeader, StatusBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { dateTime, num } from "@/lib/format";
import type { ProjectReport, Report, Run } from "@/lib/types";

export const metadata = { title: "Verification run" };

export default async function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let run: Run;
  try {
    run = await api<Run>(`/v1/verification-runs/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  const reports: Report[] = run.scope === "project" ? ((run.report as ProjectReport)?.streams ?? []) : run.report ? [run.report as Report] : [];
  return (
    <>
      <PageHeader
        title={`Verification ${run.status}`}
        description={<><span className="font-mono">{run.id}</span> · {run.scope}{run.target ? ` ${run.target}` : ""} · {num(run.eventsChecked)} events · {dateTime(run.completedAt)} · triggered by {run.trigger}</>}
        actions={<StatusBadge status={run.status} />}
      />
      <div className="space-y-6">
        {reports.map((r) => (
          <Card key={r.stream ?? r.eventId} className="overflow-hidden">
            <div className="border-b border-line px-5 py-3 text-sm font-semibold">{r.stream}</div>
            <ReportView report={r} />
          </Card>
        ))}
      </div>
    </>
  );
}
