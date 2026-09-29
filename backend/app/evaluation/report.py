"""Write JSON + Markdown evaluation reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.evaluation.types import EvalReport

DEFAULT_RESULTS_DIR = Path(__file__).resolve().parents[2] / "evaluation" / "results"


def write_reports(
    report: EvalReport,
    *,
    results_dir: Path | None = None,
    basename: str = "aegis_eval_v1",
) -> tuple[Path, Path]:
    out_dir = results_dir or DEFAULT_RESULTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump()
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()

    json_path = out_dir / f"{basename}.json"
    md_path = out_dir / f"{basename}.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_to_markdown(report, payload["generated_at"]), encoding="utf-8")
    return json_path, md_path


def _to_markdown(report: EvalReport, generated_at: str) -> str:
    d = report.detection
    lines = [
        "# AegisAI Security Evaluation v1",
        "",
        f"Generated: `{generated_at}`",
        f"Dataset: `{report.dataset_version}`",
        f"Mode: `{report.mode}`",
        f"Cases: **{report.total_cases}** (passed {report.passed}, failed {report.failed})",
        "",
        f"> {report.note}",
        "",
        "## Detection",
        "",
        f"- Precision: **{d.precision}**",
        f"- Recall: **{d.recall}**",
        f"- F1: **{d.f1}**",
        f"- FPR: **{d.false_positive_rate}**",
        f"- FNR: **{d.false_negative_rate}**",
        f"- Accuracy: **{d.accuracy}**",
        f"- TP/TN/FP/FN: {d.true_positives}/{d.true_negatives}/{d.false_positives}/{d.false_negatives}",
        "",
        "## Policy confusion",
        "",
        "```",
        json.dumps(report.policy_confusion, indent=2),
        "```",
        "",
        "## Tool firewall",
        "",
        "```",
        json.dumps(report.tool_metrics, indent=2),
        "```",
        "",
        f"## Authorization matrix: {report.auth_matrix_passed}/{report.auth_matrix_total}",
        "",
        f"## Security invariants: {report.invariants_passed}/{report.invariants_total}",
        "",
        "## Latency (ms)",
        "",
        "```",
        json.dumps(report.latency_ms, indent=2),
        "```",
        "",
        "## Category breakdown",
        "",
        "| Category | Cases | TP | FN | FP | Recall |",
        "|----------|------:|---:|---:|---:|-------:|",
    ]
    for cat, m in report.per_category.items():
        lines.append(
            f"| {cat} | {m.total} | {m.true_positives} | {m.false_negatives} | "
            f"{m.false_positives} | {m.recall} |"
        )
    lines.extend(
        [
            "",
            f"## False positives ({len(report.false_positives)})",
            "",
            ", ".join(report.false_positives) or "(none)",
            "",
            f"## False negatives ({len(report.false_negatives)})",
            "",
            ", ".join(report.false_negatives) or "(none)",
            "",
            f"## Failures ({len(report.failures)})",
            "",
        ]
    )
    for f in report.failures[:50]:
        lines.append(f"- `{f.get('case_id')}`: {f.get('reason')}")
    if len(report.failures) > 50:
        lines.append(f"- … and {len(report.failures) - 50} more")
    lines.append("")
    return "\n".join(lines)
