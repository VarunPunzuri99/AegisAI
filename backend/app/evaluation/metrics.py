"""Metric helpers for Phase 11 evaluation."""

from __future__ import annotations

from app.evaluation.types import CaseResult, DetectionMetrics


def _safe_div(n: float, d: float) -> float:
    return round(n / d, 4) if d else 0.0


def compute_detection_metrics(results: list[CaseResult]) -> DetectionMetrics:
    """Binary ATTACK vs BENIGN metrics (UNCERTAIN excluded from detection score)."""
    tp = tn = fp = fn = 0
    for r in results:
        if r.expected_label not in {"ATTACK", "BENIGN"}:
            continue
        if r.actual_label not in {"ATTACK", "BENIGN", "UNCERTAIN"}:
            continue
        exp_pos = r.expected_label == "ATTACK"
        # Treat UNCERTAIN as negative for detection (not a positive ATTACK call)
        act_pos = r.actual_label == "ATTACK"
        if exp_pos and act_pos:
            tp += 1
        elif not exp_pos and not act_pos:
            tn += 1
        elif not exp_pos and act_pos:
            fp += 1
        else:
            fn += 1
    total = tp + tn + fp + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    return DetectionMetrics(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=round(f1, 4),
        false_positive_rate=_safe_div(fp, fp + tn),
        false_negative_rate=_safe_div(fn, fn + tp),
        accuracy=_safe_div(tp + tn, total),
        total=total,
    )


def per_category_detection(
    results: list[CaseResult],
) -> dict[str, DetectionMetrics]:
    by_cat: dict[str, list[CaseResult]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)
    return {k: compute_detection_metrics(v) for k, v in sorted(by_cat.items())}


def policy_confusion(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    labels = ["ALLOW", "REVIEW", "BLOCK"]
    matrix = {e: {a: 0 for a in labels} for e in labels}
    for r in results:
        if r.expected_policy in labels and r.actual_policy in labels:
            matrix[r.expected_policy][r.actual_policy] += 1
    return matrix


def tool_security_metrics(results: list[CaseResult]) -> dict[str, float | int]:
    """Named agent-security rates (not generic accuracy)."""
    unauthorized_total = unauthorized_blocked = 0
    intent_total = intent_blocked = 0
    priv_total = priv_blocked = 0
    approval_total = approval_blocked = 0
    replay_total = replay_blocked = 0
    param_total = param_blocked = 0

    for r in results:
        if r.suite != "tool" and r.category not in {
            "tool_auth",
            "privilege_escalation",
            "approval",
            "approval_manipulation",
            "replay",
            "parameter_attack",
            "tool_abuse",
        }:
            if r.expected_tool_decision is None:
                continue

        exp = r.expected_tool_decision
        act = r.actual_tool_decision
        if exp is None:
            continue

        cid = r.case_id
        if "PRIV" in cid or r.category == "privilege_escalation":
            priv_total += 1
            if act == "DENY":
                priv_blocked += 1
        if "INTENT" in cid or (
            r.category == "tool_abuse" and exp == "DENY" and "INTENT" in cid
        ):
            intent_total += 1
            if act == "DENY":
                intent_blocked += 1
        if r.category in {"approval", "approval_manipulation"} and exp in {
            "DENY",
            "REQUIRES_APPROVAL",
        }:
            approval_total += 1
            if act in {"DENY", "REQUIRES_APPROVAL"}:
                approval_blocked += 1
        if r.category == "replay" or "REPLAY" in cid:
            replay_total += 1
            if act == "DENY":
                replay_blocked += 1
        if r.category == "parameter_attack" or "PARAM" in cid:
            param_total += 1
            if act == "DENY":
                param_blocked += 1
        if exp == "DENY":
            unauthorized_total += 1
            if act == "DENY":
                unauthorized_blocked += 1

    def rate(n: int, d: int) -> float:
        return _safe_div(float(n), float(d))

    return {
        "unauthorized_actions_total": unauthorized_total,
        "unauthorized_actions_blocked": unauthorized_blocked,
        "unauthorized_action_block_rate": rate(unauthorized_blocked, unauthorized_total),
        "intent_mismatch_total": intent_total,
        "intent_mismatch_blocked": intent_blocked,
        "intent_mismatch_block_rate": rate(intent_blocked, intent_total),
        "privilege_escalation_total": priv_total,
        "privilege_escalation_blocked": priv_blocked,
        "privilege_escalation_block_rate": rate(priv_blocked, priv_total),
        "approval_bypass_total": approval_total,
        "approval_bypass_prevented": approval_blocked,
        "approval_bypass_prevention_rate": rate(approval_blocked, approval_total),
        "replay_total": replay_total,
        "replay_blocked": replay_blocked,
        "replay_prevention_rate": rate(replay_blocked, replay_total),
        "invalid_parameter_total": param_total,
        "invalid_parameter_blocked": param_blocked,
        "invalid_parameter_block_rate": rate(param_blocked, param_total),
    }
