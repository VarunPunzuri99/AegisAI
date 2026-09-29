"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { getSystemStatus } from "@/lib/api";
import type { SystemStatus } from "@/types/security";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/scanner", label: "Scanner" },
  { href: "/attack-playground", label: "Attack Playground" },
  { href: "/agent-runtime", label: "Agent Runtime" },
  { href: "/authorization", label: "Authorization" },
  { href: "/mcp-security", label: "MCP Security" },
  { href: "/evaluation", label: "Evaluation" },
  { href: "/review-analysis", label: "Review Analysis" },
  { href: "/detection-analytics", label: "Detection Analytics" },
  { href: "/policy", label: "Policy Center" },
  { href: "/tool-security", label: "Tool Security" },
  { href: "/audit", label: "Audit Logs" },
] as const;

function NavLinks({
  pathname,
  onNavigate,
}: {
  pathname: string;
  onNavigate?: () => void;
}) {
  return (
    <nav aria-label="Primary" className="space-y-1">
      {NAV.map((item) => {
        const active =
          pathname === item.href || pathname.startsWith(`${item.href}/`);
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            className={`block rounded-sm px-3 py-2 text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-aegis-accent ${
              active
                ? "bg-aegis-ink text-white"
                : "text-aegis-slate hover:bg-aegis-steel/10"
            }`}
            aria-current={active ? "page" : undefined}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function StatusPanel({ status }: { status: SystemStatus | null }) {
  return (
    <div className="space-y-2 border-t border-aegis-steel/15 pt-4 text-xs text-aegis-mist">
      <p className="font-semibold uppercase tracking-[0.14em] text-aegis-steel">
        System status
      </p>
      <ul className="space-y-1.5">
        <li>API · {status?.api ?? "…"}</li>
        <li>Groq · {status?.groq_configured ? "configured" : "not configured"}</li>
        <li>
          Prompt Guard ·{" "}
          {status
            ? status.prompt_guard_enabled
              ? status.prompt_guard_mode
              : "disabled"
            : "…"}
        </li>
        <li>
          Safeguard ·{" "}
          {status
            ? status.safeguard_enabled
              ? status.safeguard_mode
              : "disabled"
            : "…"}
        </li>
      </ul>
      <p className="pt-2 leading-relaxed text-[11px] text-aegis-mist/80">
        Configuration only — not a live provider probe. Keys never leave the
        backend.
      </p>
    </div>
  );
}

export function DashboardShellInner({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSystemStatus()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        if (!cancelled) setStatus(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="min-h-screen bg-aegis-surface text-aegis-ink">
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top_left,_rgba(42,157,143,0.08),_transparent_45%),linear-gradient(180deg,#f4f7fb_0%,#eef2f7_100%)]"
      />

      <div className="relative mx-auto flex min-h-screen max-w-[1400px]">
        <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-aegis-steel/15 bg-white/70 px-4 py-6 backdrop-blur md:flex">
          <div className="mb-8 px-2">
            <p className="font-display text-2xl tracking-tight text-aegis-ink">
              AegisAI
            </p>
            <p className="mt-1 text-xs leading-snug text-aegis-mist">
              Agentic Prompt Injection Firewall
            </p>
          </div>
          <div className="flex-1 overflow-y-auto">
            <NavLinks pathname={pathname} />
          </div>
          <StatusPanel status={status} />
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center justify-between border-b border-aegis-steel/15 bg-white/80 px-4 py-3 backdrop-blur md:hidden">
            <div>
              <p className="font-display text-lg text-aegis-ink">AegisAI</p>
              <p className="text-[11px] text-aegis-mist">Security console</p>
            </div>
            <button
              type="button"
              className="rounded-sm border border-aegis-steel/30 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-aegis-accent"
              aria-expanded={open}
              aria-controls="mobile-nav"
              onClick={() => setOpen((v) => !v)}
            >
              Menu
            </button>
          </header>

          {open ? (
            <div
              id="mobile-nav"
              className="border-b border-aegis-steel/15 bg-white px-4 py-4 md:hidden"
            >
              <NavLinks pathname={pathname} onNavigate={() => setOpen(false)} />
              <div className="mt-4">
                <StatusPanel status={status} />
              </div>
            </div>
          ) : null}

          <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
        </div>
      </div>
    </div>
  );
}
