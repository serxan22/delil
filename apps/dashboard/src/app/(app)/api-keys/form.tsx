"use client";

import { useActionState } from "react";
import { createApiKey, type FormState } from "@/app/actions";
import { CopyButton, SubmitButton } from "@/components/client";
import { buttonClass, inputClass, Notice } from "@/components/ui";

const SCOPES: [string, string][] = [
  ["events:write", "Record events"],
  ["events:read", "Read events and streams"],
  ["verify", "Run verifications"],
  ["exports", "Create and download evidence exports"],
  ["keys:read", "List public signing keys"],
  ["keys:rotate", "Rotate and revoke signing keys"],
  ["api_keys:manage", "Manage API keys"],
];

export function CreateKeyForm() {
  const [state, action] = useActionState<FormState, FormData>(createApiKey, {});
  return (
    <form action={action} className="space-y-3 p-5 text-sm">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      {state.secret && (
        <Notice tone="ok">
          <div className="font-medium">{state.ok} Copy the secret now; it will not be shown again.</div>
          <div className="mt-2 flex items-start gap-1 rounded-md bg-surface p-2 ring-1 ring-line">
            <code className="break-all font-mono text-[12px] text-ink">{state.secret}</code>
            <CopyButton value={state.secret} />
          </div>
        </Notice>
      )}
      <label className="block space-y-1"><span className="font-medium">Name</span>
        <input name="name" required maxLength={100} placeholder="billing-service (production)" className={inputClass} />
      </label>
      <fieldset className="space-y-1.5">
        <legend className="mb-1 font-medium">Scopes</legend>
        {SCOPES.map(([s, label]) => (
          <label key={s} className="flex items-center gap-2">
            <input type="checkbox" name="scopes" value={s} defaultChecked={s === "events:write"} className="accent-accent" />
            <span className="font-mono text-[12.5px]">{s}</span><span className="text-muted">· {label}</span>
          </label>
        ))}
      </fieldset>
      <SubmitButton className={`${buttonClass.primary} w-full justify-center`}>Create API key</SubmitButton>
    </form>
  );
}
