import { Card, CardHeader, PageHeader } from "@/components/ui";
import { api } from "@/lib/api";
import type { Project } from "@/lib/types";
import { PasswordForm, SettingsForm } from "./forms";

export const metadata = { title: "Settings" };

export default async function SettingsPage() {
  const project = await api<Project>("/v1/project");
  return (
    <>
      <PageHeader title="Settings" description={`${project.name} · ${project.id}`} />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Data minimisation" description="Applied before events are hashed and stored. Redacted values never reach the database." />
          <SettingsForm settings={project.settings!} />
        </Card>
        <Card><CardHeader title="Your password" /><PasswordForm /></Card>
      </div>
    </>
  );
}
