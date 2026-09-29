"use client";

import { useCallback, useEffect, useState } from "react";
import {
  DetectionBadge,
  PolicyDecisionBadge,
  RiskBadge,
  ToolVerdictBadge,
} from "@/components/Badges";
import { MetricCard, Section } from "@/components/MetricCard";
import { PipelineVisualization } from "@/components/PipelineVisualization";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { getAuditEvent, listAuditEvents } from "@/lib/api";
import type { AuditDetail, AuditListItem, AuditListResponse } from "@/types/audit";
import type { PipelineStage } from "@/types/security";

type PolicyFilter = "ALL" | "ALLOW" | "REVIEW" | "BLOCK";
type DetectionFilter = "ALL" | "ATTACK" | "UNCERTAIN" | "BENIGN";
type SeverityFilter = "ALL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type ToolFilter = "ALL" | "ALLOW" | "DENY" | "REQUIRES_APPROVAL";

function sourceLabel(key: string) {
  if (key === "rules") return "Deterministic Rules";
  if (key === "prompt_guard") return "Prompt Guard";
  if (key === "semantic") return "Safeguard";
  return key;
}

export default function AuditPage() {
  const [policy, setPolicy] = useState<PolicyFilter>("ALL");
  const [detection, setDetection] = useState<DetectionFilter>("ALL");
  const [severity, setSeverity] = useState<SeverityFilter>("ALL");
  const [toolDecision, setToolDecision] = useState<ToolFilter>("ALL");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<AuditListResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AuditDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listAuditEvents({
        page,
        page_size: 20,
        decision: policy === "ALL" ? undefined : policy,
        detection_label: detection === "ALL" ? undefined : detection,
        severity: severity === "ALL" ? undefined : severity,
        tool_decision: toolDecision === "ALL" ? undefined : toolDecision,
      });
      setData(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit events");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [page, policy, detection, severity, toolDecision]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    setDetailError(null);
    getAuditEvent(selectedId)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setDetailError(err instanceof Error ? err.message : "Failed to load detail");
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  const summary = data?.summary ?? {};
  const items = data?.items ?? [];

  function FilterGroup<T extends string>({
    label,
    value,
    options,
    onChange,
  }: {
    label: string;
    value: T;
    options: T[];
    onChange: (v: T) => void;
  }) {
    return (
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-aegis-mist">
          {label}
        </p>
        <div className="flex flex-wrap gap-2" role="group" aria-label={label}>
          {options.map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => {
                onChange(opt);
                setPage(1);
              }}
              className={`rounded-sm border px-3 py-1.5 text-xs font-semibold tracking-wide ${
                value === opt
                  ? "border-aegis-ink bg-aegis-ink text-white"
                  : "border-aegis-steel/30 bg-white text-aegis-slate"
              }`}
              aria-pressed={value === opt}
            >
              {opt.replaceAll("_", " ")}
            </button>
          ))}
        </div>
      </div>
    );
  }

  const stages: PipelineStage[] =
    detail?.pipeline_stages.map((s) => ({
      id: s.id,
      label: s.label,
      status: s.status,
      summary: s.summary,
    })) ?? [];

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          AegisAI · Security Audit
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Persisted security events
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Structured decisions from inspect (hash + metadata only). Not a
          tamper-evident SIEM. Raw prompts and secrets are never stored.
        </p>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard label="Total events" value={String(summary.total ?? 0)} />
        <MetricCard label="Blocks" value={String(summary.blocks ?? 0)} tone="danger" />
        <MetricCard label="Reviews" value={String(summary.reviews ?? 0)} tone="warn" />
        <MetricCard label="Allows" value={String(summary.allows ?? 0)} tone="accent" />
        <MetricCard
          label="Tool denials"
          value={String(summary.tool_denials ?? 0)}
          tone="danger"
        />
      </div>

      <Section title="Filters">
        <div className="space-y-4">
          <FilterGroup
            label="Detection"
            value={detection}
            options={["ALL", "ATTACK", "UNCERTAIN", "BENIGN"]}
            onChange={setDetection}
          />
          <FilterGroup
            label="Policy"
            value={policy}
            options={["ALL", "ALLOW", "REVIEW", "BLOCK"]}
            onChange={setPolicy}
          />
          <FilterGroup
            label="Severity"
            value={severity}
            options={["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
            onChange={setSeverity}
          />
          <FilterGroup
            label="Tool decision"
            value={toolDecision}
            options={["ALL", "ALLOW", "DENY", "REQUIRES_APPROVAL"]}
            onChange={setToolDecision}
          />
        </div>
      </Section>

      <Section title="Events">
        {loading ? <LoadingState label="Loading audit events…" /> : null}
        {error ? <ErrorState title="Audit unavailable" message={error} /> : null}
        {!loading && !error && !items.length ? (
          (summary.total ?? 0) > 0 ? (
            <EmptyState
              message={`No events match the current filters (${summary.total} exist in total). Set Detection/Policy/Severity/Tool filters back to ALL.`}
            />
          ) : (
            <EmptyState message="No security events yet. Run Scanner or Attack Playground to persist decisions." />
          )
        ) : null}
        {!loading && !error && items.length ? (
          <>
            <div className="overflow-x-auto border border-aegis-steel/20 bg-white/80">
              <table className="min-w-full text-left text-sm">
                <thead className="border-b border-aegis-steel/15 text-xs uppercase tracking-[0.12em] text-aegis-mist">
                  <tr>
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Event ID</th>
                    <th className="px-3 py-2">Detection</th>
                    <th className="px-3 py-2">Risk</th>
                    <th className="px-3 py-2">Policy</th>
                    <th className="px-3 py-2">Agent</th>
                    <th className="px-3 py-2">Tool</th>
                    <th className="px-3 py-2">Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row: AuditListItem) => (
                    <tr
                      key={row.event_id}
                      className={`cursor-pointer border-b border-aegis-steel/10 last:border-0 hover:bg-aegis-surface/80 ${
                        selectedId === row.event_id ? "bg-aegis-accent/5" : ""
                      }`}
                      onClick={() => setSelectedId(row.event_id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          setSelectedId(row.event_id);
                        }
                      }}
                      tabIndex={0}
                      aria-label={`Open event ${row.event_id}`}
                    >
                      <td className="px-3 py-2 whitespace-nowrap">
                        {new Date(row.created_at).toLocaleTimeString()}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {row.event_id.slice(0, 8)}…
                      </td>
                      <td className="px-3 py-2">
                        <DetectionBadge value={row.detection_label} />
                      </td>
                      <td className="px-3 py-2">
                        <RiskBadge score={row.risk_score} severity={row.severity} />
                      </td>
                      <td className="px-3 py-2">
                        <PolicyDecisionBadge value={row.policy_decision} />
                      </td>
                      <td className="px-3 py-2 text-xs">{row.agent_state ?? "—"}</td>
                      <td className="px-3 py-2 text-xs">{row.tool_name ?? "—"}</td>
                      <td className="px-3 py-2">
                        {row.tool_decision ? (
                          <ToolVerdictBadge value={row.tool_decision} />
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-sm text-aegis-slate">
              <span>
                Page {data?.page ?? page} · {data?.total ?? 0} total
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  className="border border-aegis-steel/30 px-3 py-1 disabled:opacity-40"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="border border-aegis-steel/30 px-3 py-1 disabled:opacity-40"
                  disabled={(data?.page ?? 1) * (data?.page_size ?? 20) >= (data?.total ?? 0)}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        ) : null}
      </Section>

      {selectedId ? (
        <Section
          title="Event details"
          description="Backend-authoritative record. Content hash only — no raw prompt."
          action={
            <button
              type="button"
              className="text-sm text-aegis-accent hover:underline"
              onClick={() => setSelectedId(null)}
            >
              Close
            </button>
          }
        >
          {detailLoading ? <LoadingState label="Loading event…" /> : null}
          {detailError ? <ErrorState message={detailError} /> : null}
          {detail ? (
            <div className="space-y-6">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="border border-aegis-steel/20 bg-white/80 p-3">
                  <p className="text-xs uppercase tracking-[0.12em] text-aegis-mist">
                    Policy
                  </p>
                  <div className="mt-2">
                    <PolicyDecisionBadge value={detail.policy.decision} />
                  </div>
                </div>
                <div className="border border-aegis-steel/20 bg-white/80 p-3">
                  <p className="text-xs uppercase tracking-[0.12em] text-aegis-mist">
                    Detection
                  </p>
                  <div className="mt-2">
                    <DetectionBadge value={detail.detection.label} />
                  </div>
                </div>
                <div className="border border-aegis-steel/20 bg-white/80 p-3">
                  <p className="text-xs uppercase tracking-[0.12em] text-aegis-mist">
                    Risk
                  </p>
                  <div className="mt-2">
                    <RiskBadge
                      score={detail.risk.score}
                      severity={detail.risk.severity}
                    />
                  </div>
                </div>
                <div className="border border-aegis-steel/20 bg-white/80 p-3">
                  <p className="text-xs uppercase tracking-[0.12em] text-aegis-mist">
                    Tool
                  </p>
                  <div className="mt-2">
                    {detail.tool.decision ? (
                      <ToolVerdictBadge value={detail.tool.decision} />
                    ) : (
                      <span className="text-sm text-aegis-mist">—</span>
                    )}
                  </div>
                </div>
              </div>

              <p className="font-mono text-xs text-aegis-mist">
                hash {detail.content_hash.slice(0, 16)}… · len {detail.content_length} ·{" "}
                {new Date(detail.created_at).toLocaleString()}
              </p>

              <div className="grid gap-6 lg:grid-cols-2">
                <div>
                  <h3 className="font-display text-xl text-aegis-ink">Timeline</h3>
                  <div className="mt-3">
                    <PipelineVisualization stages={stages} />
                  </div>
                </div>
                <div>
                  <h3 className="font-display text-xl text-aegis-ink">
                    Detector evidence
                  </h3>
                  <dl className="mt-3 divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
                    {Object.entries(detail.evidence).map(([key, value]) => {
                      const v = value as {
                        label?: string;
                        score?: number;
                        confidence?: number;
                        available?: boolean;
                        invoked?: boolean;
                      };
                      return (
                        <div
                          key={key}
                          className="flex items-center justify-between gap-3 px-4 py-3 text-sm"
                        >
                          <dt>{sourceLabel(key)}</dt>
                          <dd className="flex items-center gap-2">
                            <DetectionBadge value={v.label} />
                            {v.score != null ? (
                              <span className="text-xs text-aegis-mist">
                                {v.score.toFixed(2)}
                              </span>
                            ) : null}
                            {v.confidence != null ? (
                              <span className="text-xs text-aegis-mist">
                                {v.confidence.toFixed(2)}
                              </span>
                            ) : null}
                          </dd>
                        </div>
                      );
                    })}
                  </dl>
                  {detail.reason_codes.length ? (
                    <p className="mt-3 text-sm text-aegis-slate">
                      <span className="font-medium text-aegis-ink">Codes: </span>
                      {detail.reason_codes.join(", ")}
                    </p>
                  ) : null}
                  <p className="mt-2 text-sm text-aegis-slate">
                    Agent: {detail.agent.state ?? "—"} · Tool:{" "}
                    {detail.tool.name ?? "—"}
                  </p>
                </div>
              </div>
              <p className="text-xs text-aegis-mist">{detail.note}</p>
            </div>
          ) : null}
        </Section>
      ) : null}
    </div>
  );
}
