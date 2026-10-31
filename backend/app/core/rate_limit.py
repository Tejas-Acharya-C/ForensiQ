"""Thread-safe in-memory rate limiter and concurrency guard for ForensiQ (Hardened for Phase 9C)."""

import time
from collections import defaultdict
from contextlib import contextmanager
from threading import Lock
from typing import Dict, List, Optional, Tuple, Iterator

from app.core.errors import ProcessingError


class InMemoryRateLimiter:
    """Sliding-window in-memory rate limiter with stale-key pruning and capacity bounds."""

    def __init__(self, max_keys: int = 10000, prune_interval_seconds: int = 60):
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()
        self.max_keys = max_keys
        self.prune_interval_seconds = prune_interval_seconds
        self._last_prune_time = time.monotonic()

    def _prune_stale_keys(self, now: float, window_seconds: int = 60):
        """Remove keys with no activity in the sliding window. Must be called under self._lock."""
        cutoff = now - window_seconds
        keys_to_remove = []
        for k, timestamps in list(self._requests.items()):
            valid = [t for t in timestamps if t > cutoff]
            if not valid:
                keys_to_remove.append(k)
            else:
                self._requests[k] = valid

        for k in keys_to_remove:
            self._requests.pop(k, None)

        # If capacity still exceeded, evict oldest keys
        if len(self._requests) > self.max_keys:
            sorted_keys = sorted(
                self._requests.keys(),
                key=lambda k: self._requests[k][-1] if self._requests[k] else 0,
            )
            excess = len(self._requests) - self.max_keys
            for k in sorted_keys[:excess]:
                self._requests.pop(k, None)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> Tuple[bool, int]:
        """Check if request is within allowed limit. Returns (is_allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            # Periodic stale key pruning
            if now - self._last_prune_time >= self.prune_interval_seconds or len(self._requests) >= self.max_keys:
                self._prune_stale_keys(now, window_seconds)
                self._last_prune_time = now

            timestamps = self._requests[key]
            # Prune current key timestamps
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._requests[key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                earliest = valid_timestamps[0]
                retry_after = max(1, int(window_seconds - (now - earliest)))
                return False, retry_after

            self._requests[key].append(now)

            # Cap capacity strictly
            if len(self._requests) > self.max_keys:
                self._prune_stale_keys(now, window_seconds)

            return True, 0

    def reset(self, key: Optional[str] = None):
        """Reset rate limiter state (useful for test isolation)."""
        with self._lock:
            if key:
                self._requests.pop(key, None)
            else:
                self._requests.clear()
            self._last_prune_time = time.monotonic()


class ConcurrencyGuard:
    """Lightweight in-memory active operation guard with context manager guarantee."""

    def __init__(self):
        self._active: Dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def acquire(self, key: str, max_concurrent: int = 2) -> bool:
        """Attempt to acquire a concurrency slot. Returns True if granted."""
        with self._lock:
            if self._active[key] >= max_concurrent:
                return False
            self._active[key] += 1
            return True

    def release(self, key: str):
        """Release an acquired concurrency slot."""
        with self._lock:
            if self._active[key] > 0:
                self._active[key] -= 1
                if self._active[key] == 0:
                    self._active.pop(key, None)

    @contextmanager
    def concurrency_slot(self, key: str, max_concurrent: int = 1) -> Iterator[bool]:
        """Context manager guaranteeing release on normal exit or unhandled exceptions."""
        acquired = self.acquire(key, max_concurrent=max_concurrent)
        if not acquired:
            raise ProcessingError(f"Operation on resource '{key}' is already in progress.")
        try:
            yield True
        finally:
            self.release(key)

    def reset(self):
        """Reset concurrency guard state."""
        with self._lock:
            self._active.clear()


# Global singletons
analysis_rate_limiter = InMemoryRateLimiter()
analysis_concurrency_guard = ConcurrencyGuard()
