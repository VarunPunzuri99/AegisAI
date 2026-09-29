"use client";

import { useEffect, useState } from "react";
import { DetectionBadge, PolicyDecisionBadge } from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import {
  ErrorState,
  LoadingState,
  UnavailableState,
} from "@/components/States";
import { getEvaluation } from "@/lib/api";
import type { EvaluationOverview } from "@/types/evaluation";
import { ATTACK_CATEGORY_LABELS } from "@/types/security";

function pct(n?: number | null) {
  if (n == null || Number.isNaN(n)) return "—";
  return `${(n * 100).toFixed(1)}%`;
}

export default function DetectionAnalyticsPage() {
  const [data, setData] = useState<EvaluationOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getEvaluation()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load analytics");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;
  if (!data?.available) {
    return <UnavailableState message={data?.note ?? "Evaluation data unavailable."} />;
  }

  const fusion = data.fusion_label_counts;
  const confusion = data.policy_confusion.confusion ?? {};

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Detection Analytics
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Evidence distribution
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Conflicts are intentional signals. AegisAI preserves independent
          detector evidence instead of collapsing everything into a single
          opaque model judgment.
        </p>
      </header>

      <Section title="Fusion labels">
        <div className="grid gap-3 sm:grid-cols-3">
          {(["ATTACK", "UNCERTAIN", "BENIGN"] as const).map((k) => (
            <div
              key={k}
              className="border border-aegis-steel/20 bg-white/80 p-4"
            >
              <DetectionBadge value={k} />
              <p className="mt-3 font-display text-3xl">{fusion[k] ?? 0}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-sm text-aegis-slate">
          Conflict count:{" "}
          <span className="font-semibold text-amber-900">
            {fusion.conflict ?? 0}
          </span>
        </p>
      </Section>

      <Section
        title="Policy confusion"
        description="Rows = expected policy · columns = actual policy from the evaluation run."
      >
        <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
              <tr>
                <th className="px-3 py-2">Expected \\ Actual</th>
                <th className="px-3 py-2">ALLOW</th>
                <th className="px-3 py-2">REVIEW</th>
                <th className="px-3 py-2">BLOCK</th>
              </tr>
            </thead>
            <tbody>
              {(["ALLOW", "REVIEW", "BLOCK"] as const).map((expected) => (
                <tr key={expected} className="border-b border-aegis-steel/10">
                  <td className="px-3 py-2">
                    <PolicyDecisionBadge value={expected} />
                  </td>
                  <td className="px-3 py-2">
                    {confusion[expected]?.ALLOW ?? 0}
                  </td>
                  <td className="px-3 py-2">
                    {confusion[expected]?.REVIEW ?? 0}
                  </td>
                  <td className="px-3 py-2">
                    {confusion[expected]?.BLOCK ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-sm text-aegis-slate/75">
          High REVIEW volume reflects conservative conflict/uncertainty policy —
          thresholds were not adjusted to beautify this matrix.
        </p>
      </Section>

      <Section title="Category recall">
        <ul className="divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
          {Object.entries(data.per_category)
            .filter(([c]) => c !== "benign")
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([cat, m]) => (
              <li
                key={cat}
                className="flex items-center justify-between gap-3 px-4 py-3 text-sm"
              >
                <span>{ATTACK_CATEGORY_LABELS[cat] ?? cat}</span>
                <span className="font-semibold">{pct(m.recall)}</span>
              </li>
            ))}
        </ul>
      </Section>
    </div>
  );
}
