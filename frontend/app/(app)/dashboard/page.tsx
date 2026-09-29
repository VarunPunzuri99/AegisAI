"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  DetectionBadge,
  PolicyDecisionBadge,
  SecurityStatusBadge,
} from "@/components/Badges";
import { MetricCard, Section } from "@/components/MetricCard";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  UnavailableState,
} from "@/components/States";
import { getEvaluation, getRecentActivity, getSystemStatus } from "@/lib/api";
import type { EvaluationOverview } from "@/types/evaluation";
import type { RecentActivity, SystemStatus } from "@/types/security";

function pct(n?: number | null) {
  if (n == null || Number.isNaN(n)) return "—";
  return `${(n * 100).toFixed(2)}%`;
}

export default function DashboardPage() {
  const [evalData, setEvalData] = useState<EvaluationOverview | null>(null);
  const [activity, setActivity] = useState<RecentActivity | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      getEvaluation(),
      getRecentActivity(8),
      getSystemStatus(),
    ])
      .then(([e, a, s]) => {
        if (cancelled) return;
        setEvalData(e);
        setActivity(a);
        setStatus(s);
        setError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load dashboard");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const fusion = evalData?.fusion_label_counts ?? {};
  const policyTotals = evalData?.policy_confusion?.actual_totals ?? {};

  const detectorHealth = useMemo(() => {
    const provider = evalData?.live_provider_stats ?? {};
    const pgOk = Number(provider.prompt_guard_success ?? 0);
    const pgInv = Number(provider.prompt_guard_invoked ?? 0);
    const sgOk = Number(provider.safeguard_success ?? 0);
    const sgInv = Number(provider.safeguard_invoked ?? 0);
    return { pgOk, pgInv, sgOk, sgInv };
  }, [evalData?.live_provider_stats]);

  if (loading) return <LoadingState label="Loading security overview…" />;
  if (error) return <ErrorState title="Dashboard unavailable" message={error} />;

  return (
    <div className="space-y-10">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          AegisAI Security Overview
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink sm:text-4xl">
          Defense-in-depth at a glance
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Metrics below come from the evaluation report API when available.
          They are dataset evaluation results — not a production security
          guarantee.
        </p>
      </header>

      {!evalData?.available ? (
        <UnavailableState
          message={
            evalData?.note ??
            "No evaluation result file found. Run live/offline evaluation to populate metrics."
          }
        />
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              label="Detection F1"
              value={pct(evalData.detection.f1)}
              hint={`Source: ${evalData.source} · ${evalData.mode ?? "eval"}`}
              tone="accent"
            />
            <MetricCard
              label="Precision"
              value={pct(evalData.detection.precision)}
            />
            <MetricCard label="Recall" value={pct(evalData.detection.recall)} />
            <MetricCard
              label="False positive rate"
              value={pct(evalData.detection.false_positive_rate)}
              hint={`FP count: ${evalData.detection.false_positives ?? "—"}`}
              tone="warn"
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Section title="Detection decisions">
              <dl className="divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
                {(["ATTACK", "UNCERTAIN", "BENIGN"] as const).map((k) => (
                  <div
                    key={k}
                    className="flex items-center justify-between px-4 py-3"
                  >
                    <dt>
                      <DetectionBadge value={k} />
                    </dt>
                    <dd className="font-display text-2xl text-aegis-ink">
                      {fusion[k] ?? 0}
                    </dd>
                  </div>
                ))}
                <div className="flex items-center justify-between px-4 py-3 text-sm text-aegis-slate">
                  <dt>Conflicts preserved</dt>
                  <dd className="font-semibold">{fusion.conflict ?? 0}</dd>
                </div>
              </dl>
            </Section>

            <Section
              title="Policy decisions"
              description="REVIEW means additional handling is required — not an automatic verdict of malice."
            >
              <dl className="divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
                {(["BLOCK", "REVIEW", "ALLOW"] as const).map((k) => (
                  <div
                    key={k}
                    className="flex items-center justify-between px-4 py-3"
                  >
                    <dt>
                      <PolicyDecisionBadge value={k} />
                    </dt>
                    <dd className="font-display text-2xl text-aegis-ink">
                      {policyTotals[k] ?? 0}
                    </dd>
                  </div>
                ))}
              </dl>
            </Section>
          </div>
        </>
      )}

      <Section title="Detector health">
        <div className="flex flex-wrap gap-2">
          <SecurityStatusBadge label="Deterministic Rules" ready />
          <SecurityStatusBadge
            label="Prompt Guard"
            ready={Boolean(status?.prompt_guard_enabled)}
          />
          <SecurityStatusBadge
            label="Safeguard"
            ready={Boolean(status?.safeguard_enabled)}
          />
          <SecurityStatusBadge label="Fusion" ready />
          <SecurityStatusBadge label="Risk Engine" ready />
          <SecurityStatusBadge label="Policy Engine" ready />
          <SecurityStatusBadge label="Tool Firewall" ready />
        </div>
        {evalData?.available ? (
          <p className="mt-3 text-sm text-aegis-slate/75">
            Prompt Guard {detectorHealth.pgOk}/{detectorHealth.pgInv} successful
            · Safeguard {detectorHealth.sgOk}/{detectorHealth.sgInv} successful
            (from evaluation run)
          </p>
        ) : null}
        <p className="mt-3 text-xs text-aegis-mist">
          Configured ≠ observed healthy. See{" "}
          <Link href="/review-analysis" className="underline">
            Review Analysis
          </Link>{" "}
          and provider diagnostics API for observed status / latency.
        </p>
      </Section>

      <Section
        title="Recent security activity"
        description={activity?.note}
        action={
          <Link
            href="/scanner"
            className="text-sm font-medium text-aegis-accent hover:underline"
          >
            Open scanner
          </Link>
        }
      >
        {!activity?.items.length ? (
          <EmptyState message="No scan records yet. Create a scan or run the inspector." />
        ) : (
          <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-aegis-steel/15 bg-aegis-surface/80 text-xs uppercase tracking-[0.12em] text-aegis-mist">
                <tr>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Scan ID</th>
                  <th className="px-3 py-2 font-medium">Detection</th>
                  <th className="px-3 py-2 font-medium">Risk</th>
                  <th className="px-3 py-2 font-medium">Policy</th>
                  <th className="px-3 py-2 font-medium">Tool</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {activity.items.map((row) => (
                  <tr
                    key={row.scan_id}
                    className="border-b border-aegis-steel/10 last:border-0"
                  >
                    <td className="px-3 py-2 whitespace-nowrap">{row.time}</td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {row.scan_id.slice(0, 8)}…
                    </td>
                    <td className="px-3 py-2">{row.detection ?? "—"}</td>
                    <td className="px-3 py-2">{row.risk ?? "—"}</td>
                    <td className="px-3 py-2">
                      {row.policy ? (
                        <PolicyDecisionBadge value={row.policy} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-3 py-2">{row.tool_decision ?? "—"}</td>
                    <td className="px-3 py-2">{row.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
