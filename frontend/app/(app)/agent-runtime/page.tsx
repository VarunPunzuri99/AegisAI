"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import {
  DetectionBadge,
  PolicyDecisionBadge,
  RiskBadge,
  ToolVerdictBadge,
} from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import { PipelineVisualization } from "@/components/PipelineVisualization";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { ApiError } from "@/lib/api/client";
import { listAgentScenarios, simulateAgent } from "@/lib/api";
import type {
  RuntimeScenarioSummary,
  SimulationResult,
} from "@/types/runtime";
import type { PipelineStage } from "@/types/security";

function stepIcon(status: string) {
  if (status === "ok") return "✓";
  if (status === "warn") return "⚠";
  if (status === "blocked") return "✕";
  return "·";
}

function toPipelineStages(result: SimulationResult): PipelineStage[] {
  return result.steps.map((s) => ({
    id: s.id,
    label: s.label,
    status:
      s.status === "ok"
        ? "ok"
        : s.status === "blocked"
          ? "error"
          : s.status === "warn"
            ? "unavailable"
            : s.status,
    summary: `${stepIcon(s.status)} ${s.summary}`,
  }));
}

function AgentRuntimeInner() {
  const searchParams = useSearchParams();
  const preset = searchParams.get("scenario");

  const [scenarios, setScenarios] = useState<RuntimeScenarioSummary[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    listAgentScenarios()
      .then((items) => {
        if (cancelled) return;
        setScenarios(items);
        setListError(null);
        const initial =
          preset && items.some((i) => i.scenario_id === preset)
            ? preset
            : items[0]?.scenario_id ?? null;
        setSelected(initial);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setListError(err instanceof Error ? err.message : "Failed to load scenarios");
      })
      .finally(() => {
        if (!cancelled) setLoadingList(false);
      });
    return () => {
      cancelled = true;
    };
  }, [preset]);

  useEffect(() => {
    if (!preset || loadingList || !scenarios.length) return;
    if (scenarios.some((s) => s.scenario_id === preset)) {
      void runSimulation(preset);
    }
    // Auto-run only when arriving with ?scenario=
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, loadingList, scenarios.length]);

  async function runSimulation(scenarioId: string) {
    setSelected(scenarioId);
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const sim = await simulateAgent(scenarioId);
      setResult(sim);
    } catch (err) {
      setRunError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Simulation failed",
      );
    } finally {
      setRunning(false);
    }
  }

  const active = scenarios.find((s) => s.scenario_id === selected) ?? null;

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Agent Runtime
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Simulated agent under AegisAI
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Demonstrate how AegisAI protects an agent when untrusted content tries
          to influence actions. Detection → policy → Tool Firewall → mock
          execution. No real email, shell, or external APIs.
        </p>
      </header>

      {loadingList ? <LoadingState label="Loading scenarios…" /> : null}
      {listError ? <ErrorState message={listError} /> : null}

      {!loadingList && !listError && !scenarios.length ? (
        <EmptyState message="No agent runtime scenarios returned by the API." />
      ) : null}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Section title="Scenarios" description="Deterministic demo plans (no LLM planner).">
          <ul className="space-y-2">
            {scenarios.map((s) => (
              <li key={s.scenario_id}>
                <button
                  type="button"
                  onClick={() => runSimulation(s.scenario_id)}
                  disabled={running}
                  className={`w-full border px-3 py-3 text-left text-sm transition ${
                    selected === s.scenario_id
                      ? "border-aegis-accent bg-aegis-accent/5"
                      : "border-aegis-steel/20 bg-white/80 hover:border-aegis-steel/40"
                  }`}
                >
                  <p className="font-medium text-aegis-ink">{s.title}</p>
                  <p className="mt-1 text-xs text-aegis-mist">{s.description}</p>
                </button>
              </li>
            ))}
          </ul>
        </Section>

        <div className="space-y-4">
          {running ? (
            <LoadingState label="Running agent runtime: inspect → workflow → firewall → mock…" />
          ) : null}
          {runError ? <ErrorState title="Simulation failed" message={runError} /> : null}

          {!result && !running && !runError ? (
            <EmptyState message="Select a scenario to run the agent runtime simulation." />
          ) : null}

          {result ? (
            <>
              <Section
                title="Simulation result"
                description={`${active?.title ?? result.scenario_id} · state ${result.state}`}
              >
                <div className="mb-4 flex flex-wrap items-center gap-2 border border-aegis-steel/20 bg-white/80 px-3 py-2 text-sm">
                  <PolicyDecisionBadge value={result.security.policy} />
                  <DetectionBadge value={result.security.detection} />
                  <ToolVerdictBadge value={result.security.tool_decision} />
                  <RiskBadge
                    score={result.security.risk_score}
                    severity={result.security.severity}
                  />
                  <span className="text-aegis-slate">
                    {result.execution.executed
                      ? "Mock executed"
                      : "No external action"}
                  </span>
                </div>

                <dl className="grid gap-3 text-sm sm:grid-cols-2">
                  <div className="border border-aegis-steel/15 bg-aegis-surface/60 p-3">
                    <dt className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
                      Original user intent
                    </dt>
                    <dd className="mt-1 text-aegis-ink">{result.original_intent}</dd>
                  </div>
                  <div className="border border-aegis-steel/15 bg-aegis-surface/60 p-3">
                    <dt className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
                      Untrusted content
                    </dt>
                    <dd className="mt-1 text-aegis-ink">
                      {result.untrusted_preview ?? "— (none)"}
                    </dd>
                  </div>
                  <div className="border border-aegis-steel/15 bg-aegis-surface/60 p-3">
                    <dt className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
                      Action proposal
                    </dt>
                    <dd className="mt-1 text-aegis-ink">
                      {result.action
                        ? `${result.action.tool_name ?? result.action.action_type} · risk ${result.action.risk ?? "—"} · align=${String(result.action.intent_alignment)}`
                        : "—"}
                    </dd>
                  </div>
                  <div className="border border-aegis-steel/15 bg-aegis-surface/60 p-3">
                    <dt className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
                      Audit
                    </dt>
                    <dd className="mt-1 text-aegis-ink">
                      {result.event_id ? (
                        <Link
                          href={`/audit?highlight=${result.event_id}`}
                          className="underline decoration-aegis-accent/50 underline-offset-2"
                        >
                          Event {result.event_id.slice(0, 8)}…
                        </Link>
                      ) : (
                        "Not persisted"
                      )}
                    </dd>
                  </div>
                </dl>
              </Section>

              <Section title="Runtime timeline" description="From API response — not fabricated.">
                <PipelineVisualization stages={toPipelineStages(result)} />
              </Section>

              <Section title="Security detail">
                <ul className="space-y-1 text-sm text-aegis-slate">
                  <li>Policy: {result.security.policy ?? "—"}</li>
                  <li>Tool decision: {result.security.tool_decision ?? "—"}</li>
                  <li>
                    Reason codes:{" "}
                    {result.security.reason_codes.length
                      ? result.security.reason_codes.join(", ")
                      : "—"}
                  </li>
                  <li>
                    Execution:{" "}
                    {result.execution.executed
                      ? result.execution.tool_result_summary ?? "simulated"
                      : "prevented"}
                  </li>
                  <li>
                    Tool output trusted:{" "}
                    {result.execution.trusted_output ? "yes" : "no (always untrusted)"}
                  </li>
                </ul>
                <p className="mt-4 text-xs text-aegis-mist">{result.note}</p>
              </Section>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export default function AgentRuntimePage() {
  return (
    <Suspense fallback={<LoadingState label="Loading agent runtime…" />}>
      <AgentRuntimeInner />
    </Suspense>
  );
}
