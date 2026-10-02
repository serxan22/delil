"use client";

import { useActionState } from "react";
import { verifyEvent, type FormState } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { Icon } from "@/components/icons";
import { ReportView } from "@/components/report";
import { buttonClass, Card, CardHeader, Notice } from "@/components/ui";

export function VerifyEvent({ id }: { id: string }) {
  const [state, action] = useActionState<FormState, FormData>(verifyEvent, {});
  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Verify this event"
        description="Recomputes the payload hash, event hash and signature, and checks the links to its neighbours."
      />
      <form action={action} className="p-5">
        <input type="hidden" name="id" value={id} />
        <SubmitButton className={`${buttonClass.primary} w-full justify-center`} pendingText="Verifying…">
          <Icon name="verify" />VERIFY EVENT
        </SubmitButton>
        {state.error && <div className="mt-3"><Notice tone="bad">{state.error}</Notice></div>}
      </form>
      {state.report && <div className="border-t border-line"><ReportView report={state.report} /></div>}
    </Card>
  );
}
