export default function HomePage() {
  return (
    <main className="relative min-h-screen overflow-hidden">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(42,157,143,0.18),_transparent_55%),radial-gradient(ellipse_at_bottom_right,_rgba(61,90,128,0.16),_transparent_50%),linear-gradient(180deg,#f4f7fb_0%,#e8eef6_100%)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-40 [background-size:48px_48px] [background-image:linear-gradient(to_right,rgba(61,90,128,0.07)_1px,transparent_1px),linear-gradient(to_bottom,rgba(61,90,128,0.07)_1px,transparent_1px)]"
      />

      <div className="relative mx-auto flex min-h-screen max-w-5xl flex-col px-6 py-10 sm:px-10">
        <header className="flex items-center justify-between">
          <p className="text-sm font-medium tracking-[0.2em] text-aegis-steel uppercase">
            AegisAI
          </p>
          <p className="text-sm text-aegis-mist">Phase 1 foundation</p>
        </header>

        <section className="mt-24 flex flex-1 flex-col justify-center pb-20">
          <h1 className="font-display text-5xl leading-[1.05] tracking-tight text-aegis-ink sm:text-6xl md:text-7xl">
            AegisAI
          </h1>
          <p className="mt-4 max-w-2xl text-xl font-medium text-aegis-steel sm:text-2xl">
            Agentic Prompt Injection Firewall
          </p>
          <p className="mt-8 max-w-2xl text-base leading-relaxed text-aegis-slate/80 sm:text-lg">
            AegisAI is designed as a runtime security layer that inspects
            untrusted content before it can influence an AI agent. The planned
            pipeline normalizes input, runs layered detection, scores risk,
            enforces policy, and gates tool use — with auditable decisions at
            every step.
          </p>
          <p className="mt-6 max-w-2xl text-sm leading-relaxed text-aegis-mist">
            This landing page is a development foundation only. Scanning,
            dashboards, and live detection are not implemented yet.
          </p>

          <div className="mt-12 flex flex-wrap gap-4">
            <a
              href="http://localhost:8000/health"
              className="inline-flex items-center bg-aegis-ink px-5 py-3 text-sm font-medium text-white transition hover:bg-aegis-slate"
            >
              Backend health
            </a>
            <a
              href="http://localhost:8000/docs"
              className="inline-flex items-center border border-aegis-steel/30 bg-white/60 px-5 py-3 text-sm font-medium text-aegis-ink transition hover:border-aegis-accent hover:text-aegis-accent"
            >
              API docs
            </a>
          </div>
        </section>

        <section className="border-t border-aegis-steel/15 py-10">
          <h2 className="font-display text-2xl text-aegis-ink">
            Planned architecture
          </h2>
          <p className="mt-3 max-w-3xl text-sm leading-relaxed text-aegis-slate/75">
            Ingestion and normalization feed a detection layer (deterministic
            rules, Prompt Guard, and a semantic classifier). A risk engine and
            policy engine drive allow, sanitize, quarantine, or block decisions
            before agent execution and an independent tool firewall. Full
            details live in the repository documentation.
          </p>
        </section>
      </div>
    </main>
  );
}
