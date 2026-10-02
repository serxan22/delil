"use client";

import { useActionState } from "react";
import { login, type FormState } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { buttonClass, inputClass, Notice } from "@/components/ui";

export function LoginForm() {
  const [state, action] = useActionState<FormState, FormData>(login, {});
  return (
    <form action={action} className="mt-8 space-y-4">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      <label className="block space-y-1.5">
        <span className="text-sm font-medium">Email</span>
        <input name="email" type="email" autoComplete="username" required className={inputClass} />
      </label>
      <label className="block space-y-1.5">
        <span className="text-sm font-medium">Password</span>
        <input name="password" type="password" autoComplete="current-password" required className={inputClass} />
      </label>
      <SubmitButton className={`${buttonClass.primary} w-full justify-center`} pendingText="Signing in…">Sign in</SubmitButton>
    </form>
  );
}
