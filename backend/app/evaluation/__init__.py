"""Evaluation package (Phase 6 deterministic + Phase 11 full-chain)."""

__all__ = [
    "evaluate_deterministic",
    "evaluate_full_offline",
    "load_evaluation_cases",
]


def __getattr__(name: str):
    if name in __all__:
        from app.evaluation import runner as _runner

        return getattr(_runner, name)
    raise AttributeError(name)
