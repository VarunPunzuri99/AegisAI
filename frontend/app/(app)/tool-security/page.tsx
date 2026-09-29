"use client";

import { useEffect, useState } from "react";
import { ToolVerdictBadge } from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import { ErrorState, LoadingState } from "@/components/States";
import { getTools } from "@/lib/api";
import type { ToolsOverview } from "@/types/security";

const riskTone: Record<string, string> = {
  LOW: "text-emerald-800",
  MEDIUM: "text-amber-900",
  HIGH: "text-orange-900",
  CRITICAL: "text-rose-900",
};

export default function ToolSecurityPage() {
  const [data, setData] = useState<ToolsOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getTools()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load tools");
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
          Tool Security
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Registered tools & firewall
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">{data.note}</p>
      </header>

      <Section title="Tool registry">
        <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
              <tr>
                <th className="px-3 py-2">Tool</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">Operation</th>
                <th className="px-3 py-2">Approval</th>
                <th className="px-3 py-2">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {data.tools.map((t) => (
                <tr key={t.tool_name} className="border-b border-aegis-steel/10 last:border-0">
                  <td className="px-3 py-2">
                    <p className="font-medium text-aegis-ink">{t.tool_name}</p>
                    <p className="text-xs text-aegis-mist">{t.description}</p>
                  </td>
                  <td className={`px-3 py-2 font-semibold ${riskTone[t.risk_level] ?? ""}`}>
                    {t.risk_level}
                  </td>
                  <td className="px-3 py-2">{t.operation_type}</td>
                  <td className="px-3 py-2">
                    {t.requires_approval ? "Required" : "Not required"}
                  </td>
                  <td className="px-3 py-2">{t.enabled ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Firewall controls">
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {data.controls.map((c) => (
            <li
              key={c}
              className="border border-aegis-steel/20 bg-white/80 px-3 py-3 text-sm text-aegis-slate"
            >
              {c}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Possible verdicts">
        <div className="flex flex-wrap gap-2">
          {data.verdicts.map((v) => (
            <ToolVerdictBadge key={v} value={v} />
          ))}
        </div>
      </Section>
    </div>
  );
}
