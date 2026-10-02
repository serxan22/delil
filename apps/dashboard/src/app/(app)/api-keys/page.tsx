import { revokeApiKey } from "@/app/actions";
import { ConfirmSubmit } from "@/components/client";
import { Badge, buttonClass, Card, CardHeader, EmptyState, PageHeader, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime, relative } from "@/lib/format";
import type { ApiKey, Page } from "@/lib/types";
import { CreateKeyForm } from "./form";

export const metadata = { title: "API keys" };

export default async function ApiKeysPage() {
  const { data } = await api<Page<ApiKey>>("/v1/api-keys");
  return (
    <>
      <PageHeader title="API keys" description="Project-scoped keys for your applications. Only a hash is stored; the secret is shown once. Never embed keys in browser code." />
      <div className="grid gap-6 lg:grid-cols-3">
        <Card><CardHeader title="Create key" /><CreateKeyForm /></Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Keys" />
          {data.length === 0 ? <EmptyState title="No API keys" /> : (
            <Table head={["Name", "Prefix", "Scopes", "Last used", ""]}>
              {data.map((k) => (
                <tr key={k.id} className={k.revokedAt ? "opacity-55" : ""}>
                  <Td className="font-medium">{k.name}<div className="text-[12px] font-normal text-muted">created {dateTime(k.createdAt)}</div></Td>
                  <Td mono className="text-ink-2">{k.prefix}…</Td>
                  <Td><div className="flex max-w-xs flex-wrap gap-1">{k.scopes.map((s) => <Badge key={s}>{s}</Badge>)}</div></Td>
                  <Td className="text-ink-2">{relative(k.lastUsedAt)}</Td>
                  <Td className="text-right">
                    {k.revokedAt ? <Badge tone="bad">revoked</Badge> : (
                      <form action={revokeApiKey}>
                        <input type="hidden" name="id" value={k.id} />
                        <ConfirmSubmit className={buttonClass.danger} message={`Revoke “${k.name}”? Applications using it stop working immediately.`}>Revoke</ConfirmSubmit>
                      </form>
                    )}
                  </Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
