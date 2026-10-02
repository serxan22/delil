import type { Change, Json } from "@/lib/types";

export function JsonBlock({ value }: { value: unknown }) {
  // Rendered as text: React escapes it, so event content can never inject markup.
  return (
    <pre className="max-h-[420px] overflow-auto rounded-lg bg-canvas p-4 font-mono text-[12.5px] leading-5 text-ink-2 ring-1 ring-inset ring-line">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

const show = (v: Json | undefined) => (v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v));

export function DiffTable({ changes }: { changes: Change[] }) {
  return (
    <div className="overflow-x-auto rounded-lg ring-1 ring-inset ring-line">
      <table className="w-full text-left font-mono text-[12.5px]">
        <thead className="bg-canvas text-[11px] uppercase tracking-wider text-muted">
          <tr><th className="px-3 py-2 font-medium">Path</th><th className="px-3 py-2 font-medium">Before</th><th className="px-3 py-2 font-medium">After</th></tr>
        </thead>
        <tbody className="divide-y divide-line">
          {changes.map((c) => (
            <tr key={c.path + c.op}>
              <td className="px-3 py-2 text-ink">{c.path || "/"}</td>
              <td className="px-3 py-2">{c.op !== "add" && <span className="rounded bg-bad-soft px-1 text-bad line-through decoration-bad/40">{show(c.from)}</span>}</td>
              <td className="px-3 py-2">{c.op !== "remove" && <span className="rounded bg-ok-soft px-1 text-ok">{show(c.to)}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
