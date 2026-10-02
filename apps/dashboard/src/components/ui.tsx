import type { ReactNode } from "react";
import { Icon } from "./icons";

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`rounded-xl border border-line bg-surface ${className}`}>{children}</section>;
}

export function CardHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="mt-0.5 text-[13px] text-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}

type Tone = "ok" | "bad" | "warn" | "neutral" | "accent";
const tones: Record<Tone, string> = {
  ok: "bg-ok-soft text-ok ring-ok/15",
  bad: "bg-bad-soft text-bad ring-bad/15",
  warn: "bg-warn-soft text-warn ring-warn/15",
  neutral: "bg-canvas text-ink-2 ring-line-2",
  accent: "bg-accent-soft text-accent ring-accent/15",
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status?: string }) {
  switch (status) {
    case "verified":
    case "passed":
    case "valid":
    case "completed":
    case "active":
      return <Badge tone="ok"><Icon name="check" className="size-3" />{status}</Badge>;
    case "failed":
    case "invalid":
    case "revoked":
      return <Badge tone="bad"><Icon name="x" className="size-3" />{status}</Badge>;
    case "unverified":
    case "never":
    case "pending":
    case "running":
      return <Badge tone="warn">{status}</Badge>;
    default:
      return <Badge>{status ?? "—"}</Badge>;
  }
}

export const buttonClass = {
  primary: "inline-flex h-9 items-center gap-2 rounded-lg bg-ink px-3.5 text-sm font-medium text-white hover:bg-ink-2 disabled:opacity-50",
  secondary: "inline-flex h-9 items-center gap-2 rounded-lg border border-line-2 bg-surface px-3.5 text-sm font-medium hover:bg-canvas disabled:opacity-50",
  danger: "inline-flex h-9 items-center gap-2 rounded-lg border border-bad/30 bg-surface px-3.5 text-sm font-medium text-bad hover:bg-bad-soft disabled:opacity-50",
};

export const inputClass =
  "h-9 w-full rounded-lg border border-line-2 bg-surface px-3 text-sm placeholder:text-faint focus:border-accent focus:outline-none";

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="px-5 py-4">
      <div className="text-[12px] font-medium uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-2 text-2xl font-semibold tracking-tight tabular">{value}</div>
      {hint && <div className="mt-1 text-[13px] text-muted">{hint}</div>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="px-6 py-14 text-center">
      <div className="text-sm font-medium">{title}</div>
      {children && <div className="mx-auto mt-1.5 max-w-md text-[13px] text-muted">{children}</div>}
    </div>
  );
}

export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[12px] font-medium uppercase tracking-wider text-muted">
            {head.map((h, i) => <th key={i} className="whitespace-nowrap px-5 py-2.5 font-medium">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, className = "", mono = false }: { children?: ReactNode; className?: string; mono?: boolean }) {
  return <td className={`px-5 py-3 align-top ${mono ? "font-mono text-[12.5px]" : ""} ${className}`}>{children}</td>;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-4 border-b border-line px-5 py-3 text-sm last:border-0">
      <div className="text-muted">{label}</div>
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

export function Notice({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <div className={`rounded-lg px-4 py-3 text-sm ring-1 ring-inset ${tones[tone]}`}>{children}</div>;
}
