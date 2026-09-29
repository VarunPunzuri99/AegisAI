"""Phase 11 evaluation / red-team harness tests (offline, no Groq)."""

from __future__ import annotations

from pathlib import Path

from app.evaluation.auth_matrix import run_authorization_matrix
from app.evaluation.chain import OfflineChainEvaluator
from app.evaluation.dataset_v1 import (
    DATASET_VERSION,
    build_aegis_security_eval_v1,
    dataset_summary,
)
from app.evaluation.invariants import run_security_invariants
from app.evaluation.metrics import compute_detection_metrics
from app.evaluation.report import write_reports
from app.evaluation.runner import evaluate_deterministic, evaluate_full_offline, load_evaluation_cases
from app.evaluation.types import CaseResult, DetectionMetrics, EvalReport


def test_dataset_size_and_categories() -> None:
    cases = build_aegis_security_eval_v1()
    summary = dataset_summary(cases)
    assert summary["total"] >= 145
    assert summary["benign"] >= 20
    assert summary.get("instruction_override", 0) >= 20
    for cat in (
        "role_change",
        "secret_extraction",
        "tool_abuse",
        "credential_theft",
        "context_poisoning",
        "multi_step_jailbreak",
        "encoded_instruction",
        "indirect_prompt_injection",
    ):
        assert summary.get(cat, 0) >= 15, cat
    ids = [c.case_id for c in cases]
    assert len(ids) == len(set(ids))


def test_phase6_deterministic_still_works() -> None:
    cases = load_evaluation_cases()
    assert len(cases) >= 20
    metrics = evaluate_deterministic()
    assert metrics.total > 0
    assert 0.0 <= metrics.f1 <= 1.0


def test_security_invariants() -> None:
    passed, total, failures = run_security_invariants()
    assert total >= 10
    assert passed == total, failures


def test_authorization_matrix() -> None:
    passed, total, failures = run_authorization_matrix()
    assert total >= 8
    assert passed == total, failures


def test_offline_chain_sample() -> None:
    cases = build_aegis_security_eval_v1()
    tool_cases = [c for c in cases if c.suite == "tool"][:3]
    ev = OfflineChainEvaluator()
    for case in tool_cases:
        result = ev.evaluate_case(case)
        assert result.case_id == case.case_id
        assert result.actual_tool_decision is not None


def test_full_offline_evaluation(tmp_path: Path) -> None:
    report = evaluate_full_offline(write=False)
    assert report.dataset_version == DATASET_VERSION
    assert report.total_cases >= 145
    assert report.mode == "offline"
    assert "not a production" in report.note.lower()
    assert report.invariants_passed == report.invariants_total
    assert report.auth_matrix_passed == report.auth_matrix_total
    # Detection metrics computed
    assert report.detection.total > 0
    json_path, md_path = write_reports(report, results_dir=tmp_path)
    assert json_path.exists()
    assert md_path.exists()
    assert "Precision" in md_path.read_text(encoding="utf-8")


def test_detection_metrics_helper() -> None:
    results = [
        CaseResult(
            case_id="a",
            category="x",
            suite="detection",
            passed=True,
            expected_label="ATTACK",
            actual_label="ATTACK",
        ),
        CaseResult(
            case_id="b",
            category="benign",
            suite="detection",
            passed=True,
            expected_label="BENIGN",
            actual_label="BENIGN",
        ),
    ]
    m = compute_detection_metrics(results)
    assert m.true_positives == 1
    assert m.true_negatives == 1
    assert m.f1 == 1.0


def test_red_team_flag_present() -> None:
    cases = build_aegis_security_eval_v1()
    red = [c for c in cases if c.metadata.get("red_team_v1")]
    assert len(red) >= 30
