import { rotateSigningKey } from "@/app/actions";
import { ConfirmSubmit, Hash } from "@/components/client";
import { buttonClass, Card, PageHeader, StatusBadge, Table, Td } from "@/components/ui";
import { api } from "@/lib/api";
import { dateTime, num } from "@/lib/format";
import type { Page, SigningKey } from "@/lib/types";

export const metadata = { title: "Signing keys" };

export default async function SigningKeysPage() {
  const { data } = await api<Page<SigningKey>>("/v1/signing-keys");
  return (
    <>
      <PageHeader
        title="Signing keys"
        description="Ed25519 keys that sign every event and checkpoint. Retired keys stay listed forever so historical signatures remain verifiable. Pin these fingerprints outside DƏLİL (delil keys export)."
        actions={
          <form action={rotateSigningKey}>
            <ConfirmSubmit className={buttonClass.primary} message="Rotate the signing key? The active key is retired and a new key signs all future events.">Rotate key</ConfirmSubmit>
          </form>
        }
      />
      <Card>
        <Table head={["Key", "Status", "Active window", "Events signed", "Fingerprint (SHA-256 of public key)"]}>
          {[...data].reverse().map((k) => (
            <tr key={k.id}>
              <Td mono>{k.id}<div className="mt-0.5 font-sans text-[12px] text-muted">{k.algorithm} · {k.provider} provider</div></Td>
              <Td><StatusBadge status={k.status} />{k.revocationReason && <div className="mt-1 text-[12px] text-bad">{k.revocationReason}</div>}</Td>
              <Td className="whitespace-nowrap text-[13px] text-ink-2">{dateTime(k.activatedAt)}<br />→ {k.retiredAt ? dateTime(k.retiredAt) : "now"}</Td>
              <Td className="tabular">{num(k.eventsSigned)}</Td>
              <Td><Hash value={k.fingerprint} /></Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
