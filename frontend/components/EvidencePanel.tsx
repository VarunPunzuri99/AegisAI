import {
  AttackCategoryBadge,
  DetectionBadge,
  PolicyDecisionBadge,
  RiskBadge,
  ToolVerdictBadge,
} from "@/components/Badges";
import { PipelineVisualization } from "@/components/PipelineVisualization";
import { ATTACK_CATEGORY_LABELS, type InspectResponse } from "@/types/security";

function sourceLabel(source: string) {
  if (source === "RULES") return "Deterministic Rules";
  if (source === "PROMPT_GUARD") return "Prompt Guard";
  if (source === "SEMANTIC") return "Safeguard";
  return source;
}

export function EvidencePanel({ result }: { result: InspectResponse }) {
  return (
    <div className="space-y-8">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="border border-aegis-steel/20 bg-white/80 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
            Security decision
          </p>
          <div className="mt-2">
            <PolicyDecisionBadge value={result.policy_decision} />
          </div>
        </div>
        <div className="border border-aegis-steel/20 bg-white/80 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-aegis-mist">Risk</p>
          <div className="mt-2">
            <RiskBadge score={result.risk_score} severity={result.severity} />
          </div>
        </div>
        <div className="border border-aegis-steel/20 bg-white/80 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
            Detection
          </p>
          <div className="mt-2">
            <DetectionBadge value={result.fusion_label} />
          </div>
        </div>
        <div className="border border-aegis-steel/20 bg-white/80 p-4">
          <p className="text-xs uppercase tracking-[0.14em] text-aegis-mist">
            Tool firewall
          </p>
          <div className="mt-2">
            {result.tool_firewall_ran ? (
              <ToolVerdictBadge value={result.tool_decision} />
            ) : (
              <span className="text-sm text-aegis-mist">Not evaluated</span>
            )}
          </div>
        </div>
      </div>

      {result.conflict ? (
        <div
          className="border border-amber-300/70 bg-amber-50/80 p-4"
          role="status"
          aria-live="polite"
        >
          <p className="text-sm font-semibold text-amber-950">
            Detector conflict preserved
          </p>
          <p className="mt-1 text-sm text-amber-900/80">
            Independent sources disagreed. Fusion did not hide the conflict —
            policy may force REVIEW when evidence is mixed.
          </p>
        </div>
      ) : null}

      {!result.safeguard_invoked || result.safeguard_available === false ? (
        <div className="border border-slate-300 bg-slate-50 p-4" role="status">
          <p className="text-sm font-semibold text-slate-900">
            Safeguard{" "}
            {!result.safeguard_invoked ? "not invoked" : "unavailable"}
          </p>
          <p className="mt-1 text-sm text-slate-700">
            The semantic security provider did not return a usable result.
            AegisAI preserves uncertainty and applies the configured policy —
            this is not treated as BENIGN.
          </p>
        </div>
      ) : null}

      <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div>
          <h3 className="font-display text-xl text-aegis-ink">Pipeline</h3>
          <div className="mt-4">
            <PipelineVisualization stages={result.stages} />
          </div>
        </div>

        <div className="space-y-6">
          <div>
            <h3 className="font-display text-xl text-aegis-ink">
              Detection evidence
            </h3>
            <p className="mt-1 text-xs uppercase tracking-[0.14em] text-aegis-mist">
              What was detected
            </p>
            <dl className="mt-4 divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
              {result.evidence_sources.length
                ? result.evidence_sources.map((src) => (
                    <div
                      key={src.source}
                      className="flex items-center justify-between gap-3 px-4 py-3"
                    >
                      <dt className="text-sm text-aegis-slate">
                        {sourceLabel(src.source)}
                      </dt>
                      <dd className="flex items-center gap-2">
                        <DetectionBadge value={src.label} />
                        {src.score != null ? (
                          <span className="text-xs text-aegis-mist">
                            {src.score.toFixed(2)}
                          </span>
                        ) : null}
                        {src.confidence != null ? (
                          <span className="text-xs text-aegis-mist">
                            {src.confidence.toFixed(2)}
                          </span>
                        ) : null}
                        {!src.available ? (
                          <span className="text-xs text-amber-800">unavailable</span>
                        ) : null}
                      </dd>
                    </div>
                  ))
                : (
                  <>
                    <div className="flex justify-between px-4 py-3 text-sm">
                      <span>Deterministic Rules</span>
                      <DetectionBadge value={result.rules_label} />
                    </div>
                    <div className="flex justify-between px-4 py-3 text-sm">
                      <span>Prompt Guard</span>
                      <DetectionBadge
                        value={
                          result.prompt_guard_invoked
                            ? result.prompt_guard_label
                            : "SKIPPED"
                        }
                      />
                    </div>
                    <div className="flex justify-between px-4 py-3 text-sm">
                      <span>Safeguard</span>
                      <DetectionBadge
                        value={
                          result.safeguard_invoked
                            ? result.safeguard_label
                            : "SKIPPED"
                        }
                      />
                    </div>
                  </>
                )}
              <div className="flex justify-between px-4 py-3 text-sm">
                <span>Fusion</span>
                <div className="flex items-center gap-2">
                  <DetectionBadge value={result.fusion_label} />
                  {result.conflict ? (
                    <span className="text-xs font-semibold text-amber-800">
                      ⚠ CONFLICT
                    </span>
                  ) : null}
                </div>
              </div>
            </dl>
          </div>

          <div>
            <h3 className="font-display text-xl text-aegis-ink">
              Why the system decided
            </h3>
            <p className="mt-1 text-xs uppercase tracking-[0.14em] text-aegis-mist">
              Policy rationale (backend authoritative)
            </p>
            <div className="mt-4 space-y-3 border border-aegis-steel/20 bg-white/80 p-4 text-sm text-aegis-slate">
              {result.policy_explanation ? (
                <p>{result.policy_explanation}</p>
              ) : (
                <p className="text-aegis-mist">No explanation returned.</p>
              )}
              {result.policy_reason_codes.length ? (
                <p>
                  <span className="font-medium text-aegis-ink">Codes: </span>
                  {result.policy_reason_codes.join(", ")}
                </p>
              ) : null}
              {result.safeguard_intent ? (
                <p>
                  <span className="font-medium text-aegis-ink">Intent: </span>
                  {result.safeguard_intent.replaceAll("_", " ")}
                </p>
              ) : null}
              {result.safeguard_target ? (
                <p>
                  <span className="font-medium text-aegis-ink">Target: </span>
                  {result.safeguard_target.replaceAll("_", " ")}
                </p>
              ) : null}
              {result.safeguard_impact ? (
                <p>
                  <span className="font-medium text-aegis-ink">Impact: </span>
                  {result.safeguard_impact.replaceAll("_", " ")}
                </p>
              ) : null}
            </div>
          </div>
        </div>
      </div>

      <div>
        <h3 className="font-display text-xl text-aegis-ink">Attack types</h3>
        <div className="mt-3 flex flex-wrap gap-2">
          {result.attack_types.length ? (
            result.attack_types.map((t) => (
              <AttackCategoryBadge
                key={t}
                category={ATTACK_CATEGORY_LABELS[t] ?? t}
              />
            ))
          ) : (
            <span className="text-sm text-aegis-mist">None reported</span>
          )}
        </div>
      </div>

      <div>
        <h3 className="font-display text-xl text-aegis-ink">Risk factors</h3>
        <p className="mt-1 text-sm text-aegis-slate/70">
          Values come from the backend risk engine — not recalculated here.
        </p>
        <ul className="mt-3 divide-y divide-aegis-steel/15 border border-aegis-steel/20 bg-white/80">
          {result.risk_factors.length ? (
            result.risk_factors.map((rf) => (
              <li
                key={`${rf.factor}-${rf.points}`}
                className="flex items-center justify-between gap-3 px-4 py-3 text-sm"
              >
                <span className="text-aegis-slate">
                  {rf.factor.replaceAll("_", " ")}
                  <span className="ml-2 text-xs text-aegis-mist">{rf.reason}</span>
                </span>
                <span className="font-semibold text-aegis-ink">
                  {rf.points >= 0 ? `+${rf.points}` : rf.points}
                </span>
              </li>
            ))
          ) : (
            <li className="px-4 py-3 text-sm text-aegis-mist">No factors</li>
          )}
          <li className="flex justify-between px-4 py-3 text-sm font-semibold">
            <span>Final risk</span>
            <span>
              {result.risk_score ?? "—"} / 100
              {result.severity ? ` · ${result.severity}` : ""}
            </span>
          </li>
        </ul>
      </div>

      <p className="text-xs text-aegis-mist">{result.note}</p>
    </div>
  );
}
