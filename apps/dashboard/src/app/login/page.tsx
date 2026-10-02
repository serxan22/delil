import type { Metadata } from "next";
import { Wordmark } from "@/components/logo";
import { LoginForm } from "./form";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <main className="grid min-h-screen lg:grid-cols-[1fr_520px]">
      <section className="hidden flex-col justify-between bg-ink p-12 text-white lg:flex">
        <Wordmark />
        <div className="max-w-md">
          <p className="text-[13px] uppercase tracking-[0.2em] text-white/50">Audit evidence infrastructure</p>
          <h1 className="mt-4 text-3xl font-semibold leading-tight tracking-tight">
            Every record hashed, linked and signed. Any change after the fact is detectable.
          </h1>
          <p className="mt-4 text-sm leading-6 text-white/60">
            Dəlil means “evidence” in Azerbaijani. DƏLİL makes audit trails cryptographically verifiable;
            whether they are admissible in a given proceeding depends on the applicable law.
          </p>
        </div>
        <p className="text-xs text-white/40">Built in Azerbaijan · Open source under Apache-2.0</p>
      </section>
      <section className="flex items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="lg:hidden"><Wordmark /></div>
          <h2 className="mt-8 text-xl font-semibold tracking-tight lg:mt-0">Sign in</h2>
          <p className="mt-1 text-sm text-muted">Use the administrator account created during bootstrap.</p>
          <LoginForm />
        </div>
      </section>
    </main>
  );
}
