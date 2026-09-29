"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { EvidencePanel } from "@/components/EvidencePanel";
import {
  AttackCategoryBadge,
  DetectionBadge,
  PolicyDecisionBadge,
} from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { ApiError } from "@/lib/api/client";
import { getPlayground, inspectContent } from "@/lib/api";
import {
  ATTACK_CATEGORY_LABELS,
  type InspectResponse,
  type PlaygroundScenario,
} from "@/types/security";

/** Map playground attack categories to Phase 14 agent runtime scenarios. */
const AGENT_SCENARIO_BY_CATEGORY: Record<string, string> = {
  instruction_override: "direct_prompt_injection",
  indirect_prompt_injection: "indirect_document_injection",
  tool_abuse: "intent_hijack",
  credential_theft: "direct_prompt_injection",
  secret_extraction: "direct_prompt_injection",
};

export default function AttackPlaygroundPage() {
  const [scenarios, setScenarios] = useState<PlaygroundScenario[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectResponse | null>(null);
  const [payload, setPayload] = useState<string>("");
  const resultRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    getPlayground()
      .then((items) => {
        if (cancelled) return;
        setScenarios(items);
        setListError(null);
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
  }, []);

  useEffect(() => {
    if (!result && !runError) return;
    resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result, runError]);

  async function runScenario(scenario: PlaygroundScenario) {
    setActiveId(scenario.id);
    setPayload(scenario.payload);
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const inspect = await inspectContent(scenario.payload);
      setResult(inspect);
    } catch (err) {
      setRunError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Attack run failed",
      );
    } finally {
      setRunning(false);
    }
  }

  const activeTitle =
    scenarios.find((s) => s.id === activeId)?.title ?? "Selected attack";

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Attack Playground
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Demonstrate defense-in-depth
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Each scenario sends a predefined payload through the real AegisAI
          pipeline. Use Run through Agent to continue into the Phase 14 agent
          runtime (Tool Firewall enforcement).
        </p>
      </header>

      {loadingList ? <LoadingState label="Loading scenarios…" /> : null}
      {listError ? <ErrorState message={listError} /> : null}

      {!loadingList && !listError && !scenarios.length ? (
        <EmptyState message="No playground scenarios returned by the API." />
      ) : null}

      <div ref={resultRef} className="space-y-4">
        {running ? (
          <LoadingState label="Pipeline: rules → PG → Safeguard → fusion → risk → policy → tool firewall…" />
        ) : null}
        {runError ? <ErrorState title="Run failed" message={runError} /> : null}
        {result ? (
          <Section
            title="Live pipeline result"
            description={`${activeTitle} — backend inspect response (scroll stays here after Run attack).`}
          >
            <div className="mb-4 flex flex-wrap items-center gap-2 border border-aegis-steel/20 bg-white/80 px-3 py-2 text-sm">
              <span className="text-aegis-mist">Summary</span>
              <PolicyDecisionBadge value={result.policy_decision} />
              <DetectionBadge value={result.fusion_label} />
              <span className="text-aegis-slate">
                Risk {result.risk_score ?? "—"}
                {result.severity ? ` / ${result.severity}` : ""}
              </span>
            </div>
            {payload ? (
              <pre className="mb-6 overflow-x-auto whitespace-pre-wrap border border-aegis-steel/20 bg-aegis-surface p-3 text-xs text-aegis-slate">
                {payload}
              </pre>
            ) : null}
            <EvidencePanel result={result} />
          </Section>
        ) : !running && !runError ? (
          <p className="text-sm text-aegis-mist">
            Click <strong>Run attack</strong> on a scenario. The live result
            appears in this section (above the cards).
          </p>
        ) : null}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((s) => {
          const agentScenario =
            AGENT_SCENARIO_BY_CATEGORY[s.expected_category] ??
            "direct_prompt_injection";
          return (
            <article
              key={s.id}
              className={`border bg-white/80 p-4 ${
                activeId === s.id
                  ? "border-aegis-accent"
                  : "border-aegis-steel/20"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <h2 className="font-display text-lg text-aegis-ink">{s.title}</h2>
                {activeId === s.id && result ? (
                  <PolicyDecisionBadge value={result.policy_decision} />
                ) : null}
              </div>
              <p className="mt-2 text-sm text-aegis-slate/75">{s.description}</p>
              <div className="mt-3">
                <AttackCategoryBadge
                  category={
                    ATTACK_CATEGORY_LABELS[s.expected_category] ??
                    s.expected_category
                  }
                />
              </div>
              <pre className="mt-3 max-h-28 overflow-auto whitespace-pre-wrap rounded-sm bg-aegis-surface p-2 text-xs text-aegis-slate">
                {s.payload}
              </pre>
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  className="bg-aegis-ink px-3 py-2 text-sm font-medium text-white hover:bg-aegis-slate disabled:opacity-60"
                  disabled={running}
                  onClick={() => runScenario(s)}
                >
                  {running && activeId === s.id ? "Running…" : "Run attack"}
                </button>
                <Link
                  href={`/agent-runtime?scenario=${encodeURIComponent(agentScenario)}`}
                  className="border border-aegis-steel/30 bg-white px-3 py-2 text-sm font-medium text-aegis-ink hover:border-aegis-accent"
                >
                  Run through Agent
                </Link>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
