const nf = new Intl.NumberFormat("en-US");

export const num = (n: number | undefined) => nf.format(n ?? 0);

export function dateTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function relative(iso?: string, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  const units: [number, string][] = [[60, "minute"], [3600, "hour"], [86400, "day"], [2592000, "month"]];
  let label = "";
  for (const [size, name] of units) {
    if (s >= size) {
      const v = Math.floor(s / size);
      label = `${v} ${name}${v === 1 ? "" : "s"} ago`;
    }
  }
  return label;
}

export function bytes(n?: number): string {
  if (n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const short = (h?: string, n = 12) => (h ? (h.length > n ? h.slice(0, n) + "…" : h) : "—");

export function pretty(v: unknown): string {
  return JSON.stringify(v, null, 2);
}
