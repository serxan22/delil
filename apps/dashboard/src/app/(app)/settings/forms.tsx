"use client";

import { useActionState } from "react";
import { changePassword, updateSettings, type FormState } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { buttonClass, inputClass, Notice } from "@/components/ui";
import type { ProjectSettings } from "@/lib/types";

export function SettingsForm({ settings }: { settings: ProjectSettings }) {
  const [state, action] = useActionState<FormState, FormData>(updateSettings, {});
  return (
    <form action={action} className="space-y-5 p-5 text-sm">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      {state.ok && <Notice tone="ok">{state.ok}</Notice>}
      <fieldset className="space-y-2">
        <legend className="mb-1 font-medium">Before/after states</legend>
        <label className="flex gap-2"><input type="radio" name="retainStates" value="full" defaultChecked={settings.retainStates === "full"} className="accent-accent" />
          <span>Store full states and the computed diff</span></label>
        <label className="flex gap-2"><input type="radio" name="retainStates" value="diff" defaultChecked={settings.retainStates === "diff"} className="accent-accent" />
          <span>Store only the diff (data minimisation)</span></label>
      </fieldset>
      <label className="block space-y-1"><span className="font-medium">Redaction mode</span>
        <select name="mode" defaultValue={settings.redaction.mode} className={inputClass}>
          <option value="redact">Replace with [REDACTED]</option>
          <option value="mask">Mask, keeping the last 4 characters</option>
          <option value="remove">Remove the field</option>
        </select>
      </label>
      <label className="block space-y-1"><span className="font-medium">Additional sensitive field names</span>
        <textarea name="keys" rows={3} defaultValue={settings.redaction.keys.join("\n")} placeholder={"iban\ndate_of_birth"} className={`${inputClass} h-auto py-2 font-mono`} />
        <span className="text-[12px] text-muted">Matched anywhere in before, after, data and metadata, ignoring case and punctuation. Passwords, tokens, secrets, API keys, cookies, card numbers and similar are always redacted.</span>
      </label>
      <label className="block space-y-1"><span className="font-medium">Exact paths</span>
        <textarea name="paths" rows={2} defaultValue={settings.redaction.paths.join("\n")} placeholder="/after/customer/phone" className={`${inputClass} h-auto py-2 font-mono`} />
      </label>
      <label className="flex gap-2"><input type="checkbox" name="disableDefaults" defaultChecked={settings.redaction.disableDefaults} className="accent-accent" />
        <span>Disable the built-in denylist <span className="text-muted">(not recommended)</span></span></label>
      <SubmitButton className={buttonClass.primary}>Save settings</SubmitButton>
    </form>
  );
}

export function PasswordForm() {
  const [state, action] = useActionState<FormState, FormData>(changePassword, {});
  return (
    <form action={action} className="space-y-3 p-5 text-sm">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      {state.ok && <Notice tone="ok">{state.ok}</Notice>}
      <input type="password" name="currentPassword" required autoComplete="current-password" placeholder="Current password" className={inputClass} />
      <input type="password" name="newPassword" required minLength={12} autoComplete="new-password" placeholder="New password (12+ characters)" className={inputClass} />
      <SubmitButton className={`${buttonClass.primary} w-full justify-center`}>Change password</SubmitButton>
    </form>
  );
}
