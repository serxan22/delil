"use client";

import { useActionState } from "react";
import { createProject, type FormState } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { buttonClass, inputClass, Notice } from "@/components/ui";

export function CreateProjectForm() {
  const [state, action] = useActionState<FormState, FormData>(createProject, {});
  return (
    <form action={action} className="space-y-3 p-5 text-sm">
      {state.error && <Notice tone="bad">{state.error}</Notice>}
      {state.ok && <Notice tone="ok">{state.ok}</Notice>}
      <input name="name" required maxLength={200} placeholder="HR Platform" className={inputClass} aria-label="Project name" />
      <SubmitButton className={`${buttonClass.primary} w-full justify-center`}>Create project</SubmitButton>
    </form>
  );
}
