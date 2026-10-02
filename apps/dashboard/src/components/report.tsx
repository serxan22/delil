import type { CheckStatus, Report } from "@/lib/types";
import { num } from "@/lib/format";
import { Icon } from "./icons";

const labels: [keyof Report["checks"], string][] = [
  ["hashChain", "Hash chain"],
  ["payloadHashes", "Payload hashes"],
  ["signatures", "Digital signatures"],
  ["ordering", "Ordering"],
  ["checkpoints", "Checkpoints"],
  ["streamHead", "Stream head"],
];

function Check({ status }: { status: CheckStatus }) {
  if (status === "valid") return <span className="inline-flex items-center gap-1.5 font-medium text-ok"><Icon name="check" className="size-3.5" />Valid</span>;
  if (status === "invalid") return <span className="inline-flex items-center gap-1.5 font-medium text-bad"><Icon name="x" className="size-3.5" />Invalid</span>;
  return <span className="text-faint">Not checked</span>;
}

export function ReportView({ report }: { report: Report }) {
  const ff = report.firstFailure;
  return (
    <div className="text-sm">
      <div className={`flex items-center gap-3 border-b border-line px-5 py-4 ${report.valid ? "bg-ok-soft/60" : "bg-bad-soft/70"}`}>
        <span className={`inline-flex size-8 items-center justify-center rounded-full ${report.valid ? "bg-ok text-white" : "bg-bad text-white"}`}>
          <Icon name={report.valid ? "check" : "x"} className="size-4" />
        </span>
        <div>
          <div className={`font-semibold ${report.valid ? "text-ok" : "text-bad"}`}>
            {report.valid ? "Integrity verified" : "Verification failed: tampering detected"}
          </div>
          <div className="text-[13px] text-muted">
            {num(report.eventsChecked)} events checked
            {report.eventsChecked > 0 && <> · sequences {num(report.firstSequence)}–{num(report.lastSequence)}</>}
            {" · "}{report.durationMs} ms
          </div>
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-px bg-line sm:grid-cols-3">
        {labels.map(([k, label]) => (
          <div key={k} className="bg-surface px-5 py-3">
            <dt className="text-[12px] text-muted">{label}</dt>
            <dd className="mt-0.5"><Check status={report.checks[k]} /></dd>
          </div>
        ))}
      </dl>
      {ff && (
        <div className="border-t border-line px-5 py-4">
          <div className="text-[12px] font-medium uppercase tracking-wider text-bad">First invalid event</div>
          <div className="mt-2 grid gap-1.5 font-mono text-[12.5px]">
            {ff.sequence ? <div>Sequence: {num(ff.sequence)}</div> : null}
            {ff.eventId && <div>Event: {ff.eventId}</div>}
            <div>Failure: {ff.code.replaceAll("_", " ")}</div>
            {ff.expected && <div className="break-all">Expected: {ff.expected}</div>}
            {ff.found && <div className="break-all">Found: {ff.found}</div>}
          </div>
          <p className="mt-2 text-[13px] text-ink-2">{ff.message}</p>
          <p className="mt-2 text-[13px] text-muted">Events after this point cannot be cryptographically trusted through the current chain.</p>
        </div>
      )}
      {report.failures.length > 1 && (
        <div className="border-t border-line px-5 py-4">
          <div className="text-[12px] font-medium uppercase tracking-wider text-muted">
            All failures ({num(report.failureCount)}{report.failuresTruncated ? `, first ${report.failures.length} shown` : ""})
          </div>
          <ul className="mt-2 space-y-1 font-mono text-[12px] text-ink-2">
            {report.failures.map((f, i) => <li key={i}>{f.sequence ? `#${f.sequence} ` : ""}{f.code}: {f.message}</li>)}
          </ul>
        </div>
      )}
      <div className="border-t border-line px-5 py-3 text-[12px] text-muted">
        Keys: {report.keysUsed.join(", ") || "—"}{report.keySource ? ` · trusted keys ${report.keySource}` : ""}
      </div>
    </div>
  );
}
