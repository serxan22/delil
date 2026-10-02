import Link from "next/link";
import { verifyProject } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { Icon } from "@/components/icons";
import { buttonClass, Card, CardHeader, EmptyState, PageHeader, Stat, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime, num, relative, short } from "@/lib/format";
import type { Overview } from "@/lib/types";

export const metadata = { title: "Overview" };

function Bars({ days }: { days: Overview["eventsPerDay"] }) {
  const max = Math.max(1, ...days.map((d) => d.count));
  return (
    <div className="flex h-24 items-end gap-1.5" role="img" aria-label="Events per day, last 14 days">
      {days.map((d) => (
        <div key={d.date} className="group relative flex-1">
          <div className="rounded-sm bg-accent/80 transition-colors group-hover:bg-accent" style={{ height: `${Math.max(3, (d.count / max) * 96)}px` }} />
          <div className="pointer-events-none absolute -top-7 left-1/2 hidden -translate-x-1/2 whitespace-nowrap rounded bg-ink px-1.5 py-0.5 text-[11px] text-white group-hover:block">
            {d.date.slice(5)} · {d.count}
          </div>
        </div>
      ))}
    </div>
  );
}

export default async function OverviewPage() {
  const o = await api<Overview>("/v1/overview");
  const v = o.verification;
  const health = {
    healthy: { label: "All streams verified", tone: "text-ok", bg: "bg-ok-soft" },
    failing: { label: "Integrity failure detected", tone: "text-bad", bg: "bg-bad-soft" },
    unverified: { label: "Events awaiting verification", tone: "text-warn", bg: "bg-warn-soft" },
  }[v.status];
  return (
    <>
      <PageHeader
        title="Overview"
        description={`${o.project.name}: activity and integrity at a glance.`}
        actions={
          <form action={verifyProject}>
            <SubmitButton className={buttonClass.primary} pendingText="Verifying…"><Icon name="verify" />Verify all streams</SubmitButton>
          </form>
        }
      />
      <Card className="mb-6 overflow-hidden">
        <div className={`flex flex-wrap items-center justify-between gap-4 px-5 py-4 ${health.bg}`}>
          <div className="flex items-center gap-3">
            <Icon name={v.status === "failing" ? "x" : "verify"} className={`size-5 ${health.tone}`} />
            <div>
              <div className={`font-semibold ${health.tone}`}>{health.label}</div>
              <div className="text-[13px] text-ink-2">
                {v.streamsPassing} passing · {v.streamsFailing} failing · {v.streamsUnverified} with unverified events
              </div>
            </div>
          </div>
          {v.latestRun && (
            <Link href={`/verification/${v.latestRun.id}`} className="text-sm text-ink-2 hover:text-ink">
              Last verification {relative(v.latestRun.completedAt)} · {num(v.latestRun.eventsChecked)} events →
            </Link>
          )}
        </div>
        <div className="grid grid-cols-2 divide-x divide-line border-t border-line md:grid-cols-4">
          <Stat label="Events today" value={num(o.stats.eventsToday)} hint="UTC day" />
          <Stat label="Events total" value={num(o.stats.eventsTotal)} hint={`last ${relative(o.stats.lastEventAt)}`} />
          <Stat label="Active streams" value={`${o.stats.activeStreams} / ${o.stats.streams}`} hint="events in the last 7 days" />
          <Stat label="Signing key" value={<span className="font-mono text-base">{short(o.signingKey?.fingerprint, 12)}</span>} hint={o.signingKey?.id ?? "none"} />
        </div>
      </Card>
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader title="Activity" description="Events recorded per day, last 14 days" />
          <div className="px-5 pb-5 pt-10"><Bars days={o.eventsPerDay} /></div>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Recent audit activity" action={<Link href="/events" className="text-sm text-muted hover:text-ink">All events →</Link>} />
          {o.recentEvents.length === 0 ? (
            <EmptyState title="No events yet">Send your first event with the SDK or <code>curl -X POST /v1/events</code>.</EmptyState>
          ) : (
            <Table head={["Action", "Actor", "Stream", "Recorded", "Status"]}>
              {o.recentEvents.map((e) => (
                <tr key={e.id} className="hover:bg-canvas/60">
                  <Td><Link href={`/events/${e.id}`} className="font-medium hover:underline">{e.action}</Link></Td>
                  <Td className="text-ink-2">{e.actor.displayName ?? e.actor.id}</Td>
                  <Td className="text-ink-2">{e.stream} <span className="text-faint">#{e.sequence}</span></Td>
                  <Td className="whitespace-nowrap text-ink-2" >{dateTime(e.recordedAt)}</Td>
                  <Td><StatusBadge status={e.verification?.status} /></Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
