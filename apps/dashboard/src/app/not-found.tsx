import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-3 text-center">
      <p className="text-sm text-muted">404</p>
      <h1 className="text-xl font-semibold">Not found</h1>
      <p className="max-w-sm text-sm text-muted">It does not exist, or it belongs to another organization.</p>
      <Link href="/" className="text-sm font-medium text-accent hover:underline">Back to overview</Link>
    </main>
  );
}
