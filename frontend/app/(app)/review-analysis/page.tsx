"use client";

import { useEffect, useState } from "react";
import { Section } from "@/components/MetricCard";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { getReviewAnalysis } from "@/lib/api";

export default function ReviewAnalysisPage() {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getReviewAnalysis()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load analysis");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <LoadingState label="Loading review analysis…" />;
  if (error) return <ErrorState message={error} />;
  if (!data) return null;

  if (data.available === false) {
    return (
      <EmptyState message={String(data.note ?? "No live evaluation data available.")} />
    );
  }

  const fusion = (data.fusion as Record<string, unknown>) || {};
  const policy = (data.policy as Record<string, unknown>) || {};
  const ebr = (data.expected_block_to_review as Record<string, unknown>) || {};
  const fp = (data.false_positives as Record<string, unknown>) || {};
  const fn = (data.false_negatives as Record<string, unknown>) || {};
  const uncertain = (data.uncertain_analysis as Record<string, unknown>) || {};
  const conflict = (data.conflict_analysis as Record<string, unknown>) || {};
  const latency = (data.latency_baseline_phase11_live as Record<string, unknown>) || {};

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Review Analysis
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Why REVIEW / UNCERTAIN / conflict?
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Diagnostic view from the live evaluation artifact. Thresholds were not
          changed. Evaluation dataset only — not a production security guarantee.
        </p>
      </header>

      <Section title="Fusion labels">
        <ul className="grid gap-2 sm:grid-cols-4 text-sm">
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            ATTACK: {String(fusion.ATTACK ?? "—")}
          </li>
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            BENIGN: {String(fusion.BENIGN ?? "—")}
          </li>
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            UNCERTAIN: {String(fusion.UNCERTAIN ?? "—")}
          </li>
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            Conflicts: {String(fusion.conflicts ?? "—")}
          </li>
        </ul>
      </Section>

      <Section title="Policy decisions">
        <ul className="grid gap-2 sm:grid-cols-3 text-sm">
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            ALLOW: {String(policy.ALLOW ?? "—")}
          </li>
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            REVIEW: {String(policy.REVIEW ?? "—")}
          </li>
          <li className="border border-aegis-steel/20 bg-white/80 px-3 py-3">
            BLOCK: {String(policy.BLOCK ?? "—")}
          </li>
        </ul>
      </Section>

      <Section
        title="Expected BLOCK → REVIEW"
        description={String(ebr.note ?? "")}
      >
        <p className="text-sm text-aegis-ink">
          Count: <strong>{String(ebr.count ?? "—")}</strong>
        </p>
        <p className="mt-2 text-xs text-aegis-mist">
          Sample IDs:{" "}
          {Array.isArray(ebr.sample_case_ids)
            ? (ebr.sample_case_ids as string[]).join(", ") || "—"
            : "—"}
        </p>
      </Section>

      <Section title="UNCERTAIN analysis">
        <p className="text-sm">Count: {String(uncertain.count ?? "—")}</p>
        <p className="mt-2 text-xs text-aegis-mist">{String(uncertain.note ?? "")}</p>
        <pre className="mt-3 overflow-x-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(uncertain.categories ?? {}, null, 2)}
        </pre>
      </Section>

      <Section title="Conflict analysis">
        <p className="text-sm">
          Conflict count: {String(conflict.conflict_count ?? "—")}
        </p>
        <p className="mt-2 text-xs text-aegis-mist">{String(conflict.note ?? "")}</p>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-aegis-slate">
          {Array.isArray(conflict.common_patterns)
            ? (conflict.common_patterns as string[]).map((p) => (
                <li key={p}>{p}</li>
              ))
            : null}
        </ul>
      </Section>

      <Section title="False positives (retained)">
        <p className="text-sm">
          {(fp.case_ids as string[] | undefined)?.join(", ") ?? "—"}
        </p>
        <pre className="mt-3 overflow-x-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(fp.investigation ?? {}, null, 2)}
        </pre>
      </Section>

      <Section title="False negatives (retained)">
        <p className="text-sm">
          {(fn.case_ids as string[] | undefined)?.join(", ") ?? "—"}
        </p>
        <pre className="mt-3 max-h-64 overflow-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(fn.investigation ?? {}, null, 2)}
        </pre>
      </Section>

      <Section title="Latency baseline (Phase 11 live)">
        <pre className="overflow-x-auto border border-aegis-steel/20 bg-aegis-surface p-3 text-xs">
          {JSON.stringify(latency, null, 2)}
        </pre>
      </Section>

      {typeof data.authorization_warning === "string" ? (
        <p className="text-xs text-amber-900">{data.authorization_warning}</p>
      ) : null}
    </div>
  );
}
