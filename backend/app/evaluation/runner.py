"""AegisAI evaluation entrypoint.

Offline by default (no Groq). Preserves Phase 6 deterministic harness.

Usage (from backend/):

    python -m app.evaluation.runner
    python -m app.evaluation.runner --full
    python -m app.evaluation.runner --live
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.enums import SourceType
from app.evaluation.auth_matrix import run_authorization_matrix
from app.evaluation.chain import OfflineChainEvaluator
from app.evaluation.dataset_v1 import (
    DATASET_VERSION,
    build_aegis_security_eval_v1,
    dataset_summary,
)
from app.evaluation.invariants import run_security_invariants
from app.evaluation.live_chain import LiveChainEvaluator, live_eval_settings
from app.evaluation.metrics import (
    compute_detection_metrics,
    per_category_detection,
    policy_confusion,
    tool_security_metrics,
)
from app.evaluation.report import write_reports
from app.evaluation.types import CaseResult, EvalReport
from app.services.deterministic_detection import DeterministicDetectionService
from app.services.input_normalization import InputNormalizationService

REPO_ROOT = Path(__file__).resolve().parents[3]
ATTACKS_DIR = REPO_ROOT / "datasets" / "attacks"
BENIGN_DIR = REPO_ROOT / "datasets" / "benign"


@dataclass
class EvalMetrics:
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    total: int
    dataset_note: str


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_evaluation_cases() -> list[tuple[str, bool]]:
    """Return (text, is_attack_expected) pairs from datasets/ (Phase 6 compat)."""
    cases: list[tuple[str, bool]] = []
    if ATTACKS_DIR.exists():
        for sample in sorted(ATTACKS_DIR.rglob("samples.txt")):
            for line in _load_lines(sample):
                cases.append((line, True))
    if BENIGN_DIR.exists():
        for sample in sorted(BENIGN_DIR.rglob("samples.txt")):
            for line in _load_lines(sample):
                cases.append((line, False))
    return cases


def evaluate_deterministic() -> EvalMetrics:
    """Run offline deterministic detector against Phase 6 fixtures."""
    normalizer = InputNormalizationService()
    detector = DeterministicDetectionService()
    tp = tn = fp = fn = 0

    for text, expected_attack in load_evaluation_cases():
        try:
            sec = normalizer.normalize(text, SourceType.USER_MESSAGE)
        except Exception:
            continue
        report = detector.detect(sec)
        predicted = bool(report.is_attack)
        if expected_attack and predicted:
            tp += 1
        elif not expected_attack and not predicted:
            tn += 1
        elif not expected_attack and predicted:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall)
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return EvalMetrics(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        total=total,
        dataset_note=(
            "Metrics apply only to the included evaluation dataset. "
            "They are not production performance guarantees."
        ),
    )


def _build_report_from_results(
    *,
    mode: str,
    results: list[CaseResult],
    latency_ms: dict,
    model_configuration: str,
    live_provider_stats: dict | None = None,
    offline_comparison: dict | None = None,
) -> EvalReport:
    detection_results = [
        r
        for r in results
        if r.suite == "detection"
        and not r.evidence.get("excluded_from_detection_metrics")
    ]
    detection = compute_detection_metrics(detection_results)
    per_cat = per_category_detection(detection_results)

    fps = [
        r.case_id
        for r in detection_results
        if r.expected_label == "BENIGN" and r.actual_label == "ATTACK"
    ]
    fns = [
        r.case_id
        for r in detection_results
        if r.expected_label == "ATTACK" and r.actual_label != "ATTACK"
    ]
    failures = [
        {
            "case_id": r.case_id,
            "category": r.category,
            "suite": r.suite,
            "expected_label": r.expected_label,
            "actual_label": r.actual_label,
            "expected_policy": r.expected_policy,
            "actual_policy": r.actual_policy,
            "expected_tool_decision": r.expected_tool_decision,
            "actual_tool_decision": r.actual_tool_decision,
            "reason": r.reason,
        }
        for r in results
        if not r.passed and "excluded_from_detection_metrics" not in r.reason
    ]

    fusion_counts: dict[str, int] = {}
    conflict_count = 0
    for r in results:
        if r.actual_label:
            fusion_counts[r.actual_label] = fusion_counts.get(r.actual_label, 0) + 1
        if r.evidence.get("conflict"):
            conflict_count += 1
    fusion_counts["conflict"] = conflict_count

    auth_passed, auth_total, _ = run_authorization_matrix()
    inv_passed, inv_total, _ = run_security_invariants()

    return EvalReport(
        dataset_version=DATASET_VERSION,
        mode=mode,
        total_cases=len(results),
        passed=sum(1 for r in results if r.passed),
        failed=sum(
            1
            for r in results
            if not r.passed and "excluded_from_detection_metrics" not in r.reason
        ),
        detection=detection,
        per_category=per_cat,
        policy_confusion=policy_confusion(results),
        tool_metrics=tool_security_metrics(results),
        latency_ms=latency_ms,
        false_positives=fps,
        false_negatives=fns,
        failures=failures,
        auth_matrix_passed=auth_passed,
        auth_matrix_total=auth_total,
        invariants_passed=inv_passed,
        invariants_total=inv_total,
        software_version="0.1.0",
        model_configuration=model_configuration,
        live_provider_stats=live_provider_stats or {},
        fusion_label_counts=fusion_counts,
        offline_comparison=offline_comparison or {},
    )


def evaluate_full_offline(*, write: bool = True) -> EvalReport:
    """Phase 11 full-chain offline evaluation (stubs for PG/Semantic)."""
    cases = build_aegis_security_eval_v1()
    evaluator = OfflineChainEvaluator()
    results: list[CaseResult] = []
    for case in cases:
        results.append(evaluator.evaluate_case(case))

    report = _build_report_from_results(
        mode="offline",
        results=results,
        latency_ms=evaluator.latency_summary(),
        model_configuration="offline-stubs (Prompt Guard/Safeguard not called)",
    )
    if write:
        write_reports(report)
    return report


def evaluate_full_live(*, write: bool = True) -> EvalReport:
    """
    Live Groq evaluation: rules + Prompt Guard + Safeguard + fusion + risk + policy.

    Requires RUN_GROQ_INTEGRATION_TEST=true and GROQ_API_KEY.
    """
    flag = os.getenv("RUN_GROQ_INTEGRATION_TEST", "").lower() in {"1", "true", "yes"}
    get_settings.cache_clear()
    settings = live_eval_settings()
    if not flag:
        raise RuntimeError(
            "Refusing live evaluation: set RUN_GROQ_INTEGRATION_TEST=true"
        )
    if not (settings.groq_api_key or "").strip():
        raise RuntimeError("Refusing live evaluation: GROQ_API_KEY is not configured")

    offline = evaluate_full_offline(write=False)

    cases = build_aegis_security_eval_v1()
    evaluator = LiveChainEvaluator(settings=settings)
    results: list[CaseResult] = []
    total = len(cases)
    for i, case in enumerate(cases, 1):
        results.append(evaluator.evaluate_case(case))
        if i % 10 == 0 or i == total:
            print(
                f"[live-eval] {i}/{total} "
                f"pg_ok={evaluator.stats['prompt_guard_success']} "
                f"sg_ok={evaluator.stats['safeguard_success']} "
                f"failures={len(evaluator.stats['provider_failures'])}",
                file=sys.stderr,
                flush=True,
            )

    stats = dict(evaluator.stats)
    report = _build_report_from_results(
        mode="live",
        results=results,
        latency_ms=evaluator.latency_summary(),
        model_configuration=(
            f"live Groq PG={settings.prompt_guard_model} "
            f"Safeguard={settings.safeguard_model} "
            f"modes=ALWAYS/ALWAYS"
        ),
        live_provider_stats=stats,
        offline_comparison={
            "offline_detection_f1": offline.detection.f1,
            "offline_precision": offline.detection.precision,
            "offline_recall": offline.detection.recall,
            "offline_fpr": offline.detection.false_positive_rate,
            "offline_fnr": offline.detection.false_negative_rate,
        },
    )
    if write:
        write_reports(report, basename="aegis_eval_v1_live")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAI evaluation runner")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run Phase 11 full-chain offline evaluation",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Run live Groq evaluation (requires RUN_GROQ_INTEGRATION_TEST=true "
            "and GROQ_API_KEY)"
        ),
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Do not write report files",
    )
    args = parser.parse_args()

    if args.live:
        report = evaluate_full_live(write=not args.no_write)
        summary = {
            "mode": "live",
            "dataset": report.dataset_version,
            "total": report.total_cases,
            "passed": report.passed,
            "failed": report.failed,
            "detection": {
                "precision": report.detection.precision,
                "recall": report.detection.recall,
                "f1": report.detection.f1,
                "fpr": report.detection.false_positive_rate,
                "fnr": report.detection.false_negative_rate,
                "tp": report.detection.true_positives,
                "tn": report.detection.true_negatives,
                "fp": report.detection.false_positives,
                "fn": report.detection.false_negatives,
            },
            "offline_comparison": report.offline_comparison,
            "fusion_label_counts": report.fusion_label_counts,
            "policy_confusion": report.policy_confusion,
            "tool_metrics": report.tool_metrics,
            "live_provider_stats": {
                k: v
                for k, v in report.live_provider_stats.items()
                if k != "provider_failures"
            },
            "provider_failure_count": len(
                report.live_provider_stats.get("provider_failures") or []
            ),
            "excluded_detection_count": len(
                report.live_provider_stats.get("excluded_detection_cases") or []
            ),
            "latency_ms": report.latency_ms,
            "auth_matrix": f"{report.auth_matrix_passed}/{report.auth_matrix_total}",
            "invariants": f"{report.invariants_passed}/{report.invariants_total}",
            "note": report.note,
        }
        print(json.dumps(summary, indent=2))
    elif args.full:
        report = evaluate_full_offline(write=not args.no_write)
        summary = {
            "dataset": report.dataset_version,
            "total": report.total_cases,
            "passed": report.passed,
            "failed": report.failed,
            "detection_f1": report.detection.f1,
            "auth_matrix": f"{report.auth_matrix_passed}/{report.auth_matrix_total}",
            "invariants": f"{report.invariants_passed}/{report.invariants_total}",
            "dataset_counts": dataset_summary(),
            "note": report.note,
        }
        print(json.dumps(summary, indent=2))
    else:
        metrics = evaluate_deterministic()
        print(json.dumps(asdict(metrics), indent=2))


if __name__ == "__main__":
    main()
