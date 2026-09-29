import type { PipelineStage } from "@/types/security";

function statusIcon(status: string) {
  if (status === "ok") return "✓";
  if (status === "skipped") return "–";
  if (status === "unavailable") return "!";
  if (status === "error") return "×";
  return "·";
}

export function PipelineVisualization({ stages }: { stages: PipelineStage[] }) {
  if (!stages.length) {
    return (
      <p className="text-sm text-aegis-mist">No pipeline stages yet. Run a scan.</p>
    );
  }

  return (
    <ol className="space-y-0" aria-label="Security pipeline stages">
      {stages.map((stage, index) => (
        <li key={stage.id} className="relative">
          <div className="flex items-start gap-3">
            <div className="flex w-8 flex-col items-center">
              <span
                className={`flex h-8 w-8 items-center justify-center rounded-sm border text-sm font-semibold ${
                  stage.status === "ok"
                    ? "border-aegis-accent/40 bg-aegis-accent/10 text-aegis-accent"
                    : stage.status === "unavailable" || stage.status === "error"
                      ? "border-amber-300 bg-amber-50 text-amber-900"
                      : "border-aegis-steel/25 bg-white text-aegis-mist"
                }`}
                aria-hidden
              >
                {statusIcon(stage.status)}
              </span>
              {index < stages.length - 1 ? (
                <span
                  className="my-1 h-5 w-px bg-aegis-steel/25"
                  aria-hidden
                />
              ) : null}
            </div>
            <div className="min-w-0 flex-1 pb-4">
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-aegis-mist">
                {stage.label}
              </p>
              <p className="mt-0.5 text-sm font-medium text-aegis-ink">
                {stage.summary}
                {stage.detail ? (
                  <span className="ml-2 font-normal text-aegis-slate/70">
                    {stage.detail}
                  </span>
                ) : null}
              </p>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
