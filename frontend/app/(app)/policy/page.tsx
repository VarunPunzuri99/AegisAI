"use client";

import { useEffect, useState } from "react";
import { PolicyDecisionBadge } from "@/components/Badges";
import { AttackCategoryBadge } from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import { ErrorState, LoadingState } from "@/components/States";
import { getPolicy } from "@/lib/api";
import type { PolicyOverview } from "@/types/security";

export default function PolicyPage() {
  const [data, setData] = useState<PolicyOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getPolicy()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load policy");
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
  if (!data) return null;

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Policy Center
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          {data.policy_id}
        </h1>
        <p className="mt-1 text-sm text-aegis-mist">
          Version {data.version} · read-only
        </p>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">{data.note}</p>
      </header>

      <Section title="Risk bands">
        <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
              <tr>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Decision</th>
              </tr>
            </thead>
            <tbody>
              {data.bands.map((b) => (
                <tr key={b.range} className="border-b border-aegis-steel/10 last:border-0">
                  <td className="px-3 py-2 font-mono">{b.range}</td>
                  <td className="px-3 py-2">{b.severity}</td>
                  <td className="px-3 py-2">
                    <PolicyDecisionBadge value={b.decision} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Special rules">
        <ul className="list-disc space-y-2 pl-5 text-sm text-aegis-slate">
          {data.special_rules.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </Section>

      <Section title="High-impact categories">
        <div className="flex flex-wrap gap-2">
          {data.high_impact_categories.map((c) => (
            <AttackCategoryBadge key={c} category={c} />
          ))}
        </div>
      </Section>
    </div>
  );
}
