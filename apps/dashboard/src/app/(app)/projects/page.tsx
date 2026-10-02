import { switchProject } from "@/app/actions";
import { SubmitButton } from "@/components/client";
import { Badge, buttonClass, Card, CardHeader, PageHeader, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime } from "@/lib/format";
import { selectedProject } from "@/lib/session";
import type { Page, Project } from "@/lib/types";
import { CreateProjectForm } from "./form";

export const metadata = { title: "Projects" };

export default async function ProjectsPage() {
  const [{ data }, current] = await Promise.all([api<Page<Project>>("/v1/projects", { noProject: true }), selectedProject()]);
  return (
    <>
      <PageHeader title="Projects" description="Projects isolate streams, API keys and signing keys within your organization." />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card><CardHeader title="New project" description="Gets its own Ed25519 signing key." /><CreateProjectForm /></Card>
        <Card className="lg:col-span-2">
          <Table head={["Project", "Slug", "Created", ""]}>
            {data.map((p) => (
              <tr key={p.id}>
                <Td className="font-medium">{p.name}<div className="font-mono text-[12px] font-normal text-muted">{p.id}</div></Td>
                <Td mono className="text-ink-2">{p.slug}</Td>
                <Td className="text-ink-2">{dateTime(p.createdAt)}</Td>
                <Td className="text-right">
                  {p.id === current ? <Badge tone="accent">current</Badge> : (
                    <form action={switchProject}><input type="hidden" name="projectId" value={p.id} />
                      <SubmitButton className={buttonClass.secondary}>Switch</SubmitButton></form>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>
    </>
  );
}
