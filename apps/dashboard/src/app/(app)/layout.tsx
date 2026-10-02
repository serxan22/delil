import { logout, switchProject } from "@/app/actions";
import { NavLink, ProjectSwitcher } from "@/components/client";
import { Icon } from "@/components/icons";
import { Wordmark } from "@/components/logo";
import { api } from "@/lib/api";
import { selectedProject } from "@/lib/session";
import type { Session } from "@/lib/types";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await api<Session>("/v1/auth/session", { noProject: true });
  const current = (await selectedProject()) ?? session.projects[0]?.id ?? "";
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-64 shrink-0 flex-col border-r border-line bg-canvas px-4 py-5">
        <div className="px-1.5"><Wordmark /></div>
        <div className="mt-6 px-0.5">
          <div className="mb-1.5 px-1 text-[11px] font-medium uppercase tracking-wider text-faint">{session.tenant.name}</div>
          <ProjectSwitcher projects={session.projects} current={current} action={switchProject} />
        </div>
        <nav className="mt-6 space-y-0.5">
          <NavLink href="/" icon="overview">Overview</NavLink>
          <NavLink href="/events" icon="events">Events</NavLink>
          <NavLink href="/streams" icon="streams">Streams</NavLink>
          <NavLink href="/verification" icon="verify">Verification</NavLink>
          <NavLink href="/exports" icon="exports">Evidence exports</NavLink>
        </nav>
        <nav className="mt-6 space-y-0.5">
          <div className="mb-1.5 px-2.5 text-[11px] font-medium uppercase tracking-wider text-faint">Administration</div>
          <NavLink href="/api-keys" icon="apiKeys">API keys</NavLink>
          <NavLink href="/signing-keys" icon="signingKeys">Signing keys</NavLink>
          <NavLink href="/projects" icon="projects">Projects</NavLink>
          <NavLink href="/settings" icon="settings">Settings</NavLink>
        </nav>
        <div className="mt-auto space-y-3 px-1.5">
          <div className="rounded-lg border border-line bg-surface px-3 py-2.5">
            <div className="truncate text-sm font-medium">{session.user.displayName}</div>
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-xs text-muted">{session.user.email} · {session.user.role}</span>
              <form action={logout}>
                <button type="submit" title="Sign out" aria-label="Sign out" className="text-faint hover:text-ink">
                  <Icon name="logout" className="size-4" />
                </button>
              </form>
            </div>
          </div>
          <p className="text-[11px] leading-4 text-faint">DƏLİL v0.1 · Built in Azerbaijan</p>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-10 py-9">
        <div className="mx-auto max-w-6xl">{children}</div>
      </main>
    </div>
  );
}
