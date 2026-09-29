"""In-memory action-id replay registry (test/dev; production needs durable store)."""

from __future__ import annotations

from threading import Lock
from uuid import UUID


class ActionReplayRegistry:
    """
    Tracks processed action_ids to reject duplicate execution attempts.

    Production should use durable/atomic storage; this is process-local only.
    """

    def __init__(self) -> None:
        self._processed: set[UUID] = set()
        self._lock = Lock()

    def is_processed(self, action_id: UUID) -> bool:
        with self._lock:
            return action_id in self._processed

    def mark_processed(self, action_id: UUID) -> bool:
        """
        Mark action as processed.

        Returns True if newly marked, False if already present (replay).
        """
        with self._lock:
            if action_id in self._processed:
                return False
            self._processed.add(action_id)
            return True

    def clear(self) -> None:
        with self._lock:
            self._processed.clear()


# Shared default for app/tests; tests may construct isolated instances.
DEFAULT_REPLAY_REGISTRY = ActionReplayRegistry()
