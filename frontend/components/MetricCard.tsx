import type { ReactNode } from "react";

type Props = {
  label: string;
  value: string;
  hint?: string;
  tone?: "default" | "accent" | "warn" | "danger";
};

const tones: Record<NonNullable<Props["tone"]>, string> = {
  default: "border-aegis-steel/20 bg-white/80",
  accent: "border-aegis-accent/35 bg-aegis-accent/5",
  warn: "border-aegis-highlight/50 bg-aegis-highlight/10",
  danger: "border-rose-300/60 bg-rose-50",
};

export function MetricCard({ label, value, hint, tone = "default" }: Props) {
  return (
    <article
      className={`rounded-sm border px-4 py-4 shadow-sm ${tones[tone]}`}
      aria-label={`${label}: ${value}`}
    >
      <p className="text-xs font-medium uppercase tracking-[0.14em] text-aegis-mist">
        {label}
      </p>
      <p className="mt-2 font-display text-3xl tracking-tight text-aegis-ink">
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-aegis-slate/70">{hint}</p> : null}
    </article>
  );
}

export function Section({
  title,
  description,
  children,
  action,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="font-display text-2xl text-aegis-ink">{title}</h2>
          {description ? (
            <p className="mt-1 max-w-3xl text-sm text-aegis-slate/75">
              {description}
            </p>
          ) : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
