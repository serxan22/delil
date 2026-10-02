"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { Icon, type IconName } from "./icons";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
      className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-faint hover:bg-canvas hover:text-ink"
    >
      <Icon name={done ? "check" : "copy"} className="size-3.5" />
    </button>
  );
}

/** A hash or signature, shown in full with a copy button. */
export function Hash({ value, className = "" }: { value: string; className?: string }) {
  return (
    <span className={`group inline-flex max-w-full items-start gap-1 ${className}`}>
      <code className="break-all font-mono text-[12.5px] leading-5 text-ink-2">{value}</code>
      <CopyButton value={value} />
    </span>
  );
}

export function NavLink({ href, icon, children }: { href: string; icon: IconName; children: ReactNode }) {
  const path = usePathname();
  const active = href === "/" ? path === "/" : path === href || path.startsWith(href + "/");
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors ${
        active ? "bg-surface font-medium text-ink shadow-[0_1px_2px_rgba(0,0,0,0.06)] ring-1 ring-line" : "text-ink-2 hover:bg-white/60"
      }`}
    >
      <Icon name={icon} className={`size-4 ${active ? "text-accent" : "text-faint"}`} />
      {children}
    </Link>
  );
}

export function SubmitButton({ children, className, pendingText }: { children: ReactNode; className: string; pendingText?: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" disabled={pending} className={className}>
      {pending ? (pendingText ?? "Working…") : children}
    </button>
  );
}

export function ConfirmSubmit({ children, className, message }: { children: ReactNode; className: string; message: string }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className={className}
      onClick={(e) => {
        if (!window.confirm(message)) e.preventDefault();
      }}
    >
      {pending ? "Working…" : children}
    </button>
  );
}

export function ProjectSwitcher({ projects, current, action }: {
  projects: { id: string; name: string }[];
  current: string;
  action: (formData: FormData) => void;
}) {
  return (
    <form action={action}>
      <label className="sr-only" htmlFor="project">Project</label>
      <select
        id="project"
        name="projectId"
        defaultValue={current}
        onChange={(e) => e.currentTarget.form?.requestSubmit()}
        className="h-9 w-full rounded-lg border border-line-2 bg-surface px-2.5 text-sm font-medium"
      >
        {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
    </form>
  );
}
