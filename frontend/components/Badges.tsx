const base =
  "inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs font-semibold tracking-wide";

export function PolicyDecisionBadge({ value }: { value?: string | null }) {
  const v = (value ?? "—").toUpperCase();
  const styles: Record<string, string> = {
    ALLOW: "border-emerald-300 bg-emerald-50 text-emerald-900",
    REVIEW: "border-amber-300 bg-amber-50 text-amber-950",
    BLOCK: "border-rose-300 bg-rose-50 text-rose-950",
    ERROR: "border-slate-400 bg-slate-100 text-slate-900",
  };
  return (
    <span className={`${base} ${styles[v] ?? "border-aegis-steel/30 bg-white text-aegis-ink"}`}>
      <span aria-hidden>{v === "ALLOW" ? "○" : v === "REVIEW" ? "◐" : v === "BLOCK" ? "●" : "–"}</span>
      {v}
    </span>
  );
}

export function DetectionBadge({ value }: { value?: string | null }) {
  const v = (value ?? "—").toUpperCase();
  const styles: Record<string, string> = {
    ATTACK: "border-rose-300 bg-rose-50 text-rose-950",
    BENIGN: "border-emerald-300 bg-emerald-50 text-emerald-900",
    UNCERTAIN: "border-amber-300 bg-amber-50 text-amber-950",
    UNAVAILABLE: "border-slate-300 bg-slate-100 text-slate-800",
  };
  return (
    <span className={`${base} ${styles[v] ?? "border-aegis-steel/30 bg-white text-aegis-ink"}`}>
      {v}
    </span>
  );
}

export function ToolVerdictBadge({ value }: { value?: string | null }) {
  const v = (value ?? "—").toUpperCase();
  const styles: Record<string, string> = {
    ALLOW: "border-emerald-300 bg-emerald-50 text-emerald-900",
    DENY: "border-rose-300 bg-rose-50 text-rose-950",
    REQUIRES_APPROVAL: "border-amber-300 bg-amber-50 text-amber-950",
  };
  return (
    <span className={`${base} ${styles[v] ?? "border-aegis-steel/30 bg-white text-aegis-ink"}`}>
      {v.replaceAll("_", " ")}
    </span>
  );
}

export function RiskBadge({
  score,
  severity,
}: {
  score?: number | null;
  severity?: string | null;
}) {
  if (score == null) {
    return <span className={`${base} border-aegis-steel/30 bg-white`}>—</span>;
  }
  return (
    <span className={`${base} border-aegis-steel/30 bg-white text-aegis-ink`}>
      {score} / 100
      {severity ? <span className="font-normal text-aegis-mist">· {severity}</span> : null}
    </span>
  );
}

export function AttackCategoryBadge({ category }: { category: string }) {
  return (
    <span className={`${base} border-aegis-steel/25 bg-aegis-surface text-aegis-slate`}>
      {category.replaceAll("_", " ")}
    </span>
  );
}

export function SecurityStatusBadge({
  label,
  ready,
}: {
  label: string;
  ready: boolean;
}) {
  return (
    <span
      className={`${base} ${
        ready
          ? "border-emerald-300 bg-emerald-50 text-emerald-900"
          : "border-slate-300 bg-slate-100 text-slate-700"
      }`}
    >
      <span aria-hidden>{ready ? "●" : "○"}</span>
      {label}: {ready ? "READY" : "OFF / UNKNOWN"}
    </span>
  );
}
