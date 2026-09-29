"use client";

import { useEffect, useState } from "react";
import { MetricCard, Section } from "@/components/MetricCard";
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
  return `${(n * 100).toFixed(2)}%`;
}

export default function EvaluationPage() {
  const [data, setData] = useState<EvaluationOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getEvaluation()
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load evaluation");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <LoadingState label="Loading evaluation…" />;
  if (error) return <ErrorState message={error} />;
  if (!data?.available) {
    return (
      <UnavailableState
        message={
          data?.note ??
          "No evaluation report on disk. Run the evaluation runner first."
        }
      />
    );
  }

  const offline = data.offline_comparison ?? {};
  const scored = data.detection.total;

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Evaluation
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          {data.dataset_version ?? "Dataset evaluation"}
        </h1>
        <p className="mt-2 max-w-3xl rounded-sm border border-amber-300/60 bg-amber-50 px-3 py-2 text-sm text-amber-950">
          Dataset evaluation only. Not a production security guarantee.
        </p>
        <p className="mt-2 text-sm text-aegis-slate/70">
          Source file: {data.source} · mode:{" "}
          <span className="font-semibold uppercase tracking-wide text-aegis-ink">
            {data.mode ?? "—"}
          </span>
          {data.generated_at ? ` · generated ${data.generated_at}` : ""}
        </p>
        <p className="mt-1 text-xs text-aegis-mist">
          Explicitly distinguish OFFLINE (stubbed PG/Safeguard) vs LIVE (real Groq).
          Metrics are not interchangeable if config changed.
        </p>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total cases" value={String(data.total_cases ?? "—")} />
        <MetricCard label="Detection scored" value={String(scored ?? "—")} />
        <MetricCard label="F1" value={pct(data.detection.f1)} tone="accent" />
        <MetricCard label="FPR" value={pct(data.detection.false_positive_rate)} />
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Precision" value={pct(data.detection.precision)} />
        <MetricCard label="Recall" value={pct(data.detection.recall)} />
        <MetricCard label="FNR" value={pct(data.detection.false_negative_rate)} />
        <MetricCard
          label="TP / TN / FP / FN"
          value={`${data.detection.true_positives ?? "—"} / ${data.detection.true_negatives ?? "—"} / ${data.detection.false_positives ?? "—"} / ${data.detection.false_negatives ?? "—"}`}
        />
      </div>

      <Section
        title="Offline vs live"
        description="Layered detectors improve recall vs rules-only offline evaluation."
      >
        <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
              <tr>
                <th className="px-3 py-2">Metric</th>
                <th className="px-3 py-2">Offline</th>
                <th className="px-3 py-2">Live</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-aegis-steel/10">
                <td className="px-3 py-2">F1</td>
                <td className="px-3 py-2">{pct(offline.offline_detection_f1)}</td>
                <td className="px-3 py-2 font-semibold">{pct(data.detection.f1)}</td>
              </tr>
              <tr className="border-b border-aegis-steel/10">
                <td className="px-3 py-2">Precision</td>
                <td className="px-3 py-2">{pct(offline.offline_precision)}</td>
                <td className="px-3 py-2 font-semibold">
                  {pct(data.detection.precision)}
                </td>
              </tr>
              <tr className="border-b border-aegis-steel/10">
                <td className="px-3 py-2">Recall</td>
                <td className="px-3 py-2">{pct(offline.offline_recall)}</td>
                <td className="px-3 py-2 font-semibold">
                  {pct(data.detection.recall)}
                </td>
              </tr>
              <tr>
                <td className="px-3 py-2">FPR</td>
                <td className="px-3 py-2">{pct(offline.offline_fpr)}</td>
                <td className="px-3 py-2 font-semibold">
                  {pct(data.detection.false_positive_rate)}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Per-category recall">
        <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
              <tr>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Cases</th>
                <th className="px-3 py-2">TP</th>
                <th className="px-3 py-2">FN</th>
                <th className="px-3 py-2">FP</th>
                <th className="px-3 py-2">Recall</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.per_category)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([cat, m]) => (
                  <tr key={cat} className="border-b border-aegis-steel/10 last:border-0">
                    <td className="px-3 py-2">
                      {ATTACK_CATEGORY_LABELS[cat] ?? cat}
                    </td>
                    <td className="px-3 py-2">{m.total ?? "—"}</td>
                    <td className="px-3 py-2">{m.true_positives ?? "—"}</td>
                    <td className="px-3 py-2">{m.false_negatives ?? "—"}</td>
                    <td className="px-3 py-2">{m.false_positives ?? "—"}</td>
                    <td className="px-3 py-2">{pct(m.recall)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </Section>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="border border-aegis-steel/20 bg-white/80 p-4 text-sm">
          <p className="font-semibold text-aegis-ink">Auth matrix</p>
          <p className="mt-1 text-aegis-slate">{data.auth_matrix ?? "—"}</p>
        </div>
        <div className="border border-aegis-steel/20 bg-white/80 p-4 text-sm">
          <p className="font-semibold text-aegis-ink">Invariants</p>
          <p className="mt-1 text-aegis-slate">{data.invariants ?? "—"}</p>
        </div>
      </div>

      <Section
        title="Fusion / uncertainty (dataset)"
        description="Evaluation dataset only — not production traffic."
      >
        <ul className="grid gap-2 sm:grid-cols-3 text-sm">
          {Object.entries(data.fusion_label_counts ?? {}).map(([k, v]) => (
            <li
              key={k}
              className="border border-aegis-steel/20 bg-white/80 px-3 py-3"
            >
              {k}: {String(v)}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Provider success (live stats from report)">
        <pre className="overflow-x-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(data.live_provider_stats ?? {}, null, 2)}
        </pre>
      </Section>

      <Section title="Latency (from evaluation report)">
        <pre className="overflow-x-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(data.latency_ms ?? {}, null, 2)}
        </pre>
        <p className="mt-2 text-xs text-aegis-mist">
          See also Review Analysis for Phase 11 live baseline preservation.
        </p>
      </Section>

      <Section title="False positives / negatives (retained)">
        <p className="text-sm">
          FP: {(data.false_positives ?? []).join(", ") || "—"}
        </p>
        <p className="mt-1 text-sm">
          FN: {(data.false_negatives ?? []).join(", ") || "—"}
        </p>
      </Section>
    </div>
  );
}
