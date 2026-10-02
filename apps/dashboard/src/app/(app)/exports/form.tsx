"use client";

import { useActionState } from "react";
import { createExport, type FormState } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { buttonClass, inputClass, Notice } from "@/components/ui";

export function ExportForm({ streams }: { streams: string[] }) {
  const [state, action] = useActionState<FormState, FormData>(createExport, {});
  return (
    <form action={action} className="space-y-3 p-5 text-sm">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      {state.ok && <Notice tone="ok">{state.ok}</Notice>}
      <label className="block space-y-1"><span className="font-medium">Stream</span>
        <select name="stream" required className={inputClass}>{streams.map((s) => <option key={s}>{s}</option>)}</select>
      </label>
      <div className="grid grid-cols-2 gap-3">
        <label className="block space-y-1"><span className="font-medium">From</span><input type="date" name="from" className={inputClass} /></label>
        <label className="block space-y-1"><span className="font-medium">To</span><input type="date" name="to" className={inputClass} /></label>
      </div>
      <details className="rounded-lg border border-line px-3 py-2">
        <summary className="cursor-pointer text-muted">Disclosure filters</summary>
        <div className="mt-3 space-y-2">
          <input name="actorId" placeholder="Actor id" className={inputClass} />
          <input name="action" placeholder="Action" className={inputClass} />
          <input name="resourceType" placeholder="Resource type" className={inputClass} />
          <input name="resourceId" placeholder="Resource id" className={inputClass} />
        </div>
      </details>
      <SubmitButton className={`${buttonClass.primary} w-full justify-center`} pendingText="Queuing…">Create evidence package</SubmitButton>
    </form>
  );
}
