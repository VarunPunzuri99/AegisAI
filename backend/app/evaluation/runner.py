"""Hackathon evaluation harness for the deterministic detector (offline by default).

Metrics apply only to the bundled dataset — not production guarantees.

Usage (from backend/):

    python -m app.evaluation.runner

Optional semantic/Groq evaluation is opt-in later; this runner is deterministic-only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.enums import SourceType
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
    """Return (text, is_attack_expected) pairs from datasets/."""
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
    """Run offline deterministic detector against bundled fixtures."""
    normalizer = InputNormalizationService()
    detector = DeterministicDetectionService()
    tp = tn = fp = fn = 0

    for text, expected_attack in load_evaluation_cases():
        try:
            sec = normalizer.normalize(text, SourceType.USER_MESSAGE)
        except Exception:
            # Malformed fixture lines — skip
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


def main() -> None:
    metrics = evaluate_deterministic()
    print(json.dumps(asdict(metrics), indent=2))


if __name__ == "__main__":
    main()
