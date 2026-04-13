"""Atomic token budget counter with reservation."""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

class TokenBudget:
    """Thread-safe token budget with reservation system."""

    def __init__(self, max_tokens: int | None = None, layer3_fraction: float = 0.4):
        self.max_tokens = max_tokens
        self.layer3_fraction = layer3_fraction
        self._used = 0
        self._reserved = 0
        self._lock = asyncio.Lock()

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int | None:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self._used - self._reserved)

    @property
    def layer3_budget(self) -> int | None:
        if self.max_tokens is None:
            return None
        return int(self.max_tokens * self.layer3_fraction)

    async def reserve(self, estimated_tokens: int) -> bool:
        """Reserve tokens before an LLM call. Returns False if budget exceeded."""
        async with self._lock:
            if self.max_tokens is None:
                return True
            if self._used + self._reserved + estimated_tokens > self.max_tokens:
                return False
            self._reserved += estimated_tokens
            return True

    async def commit(self, reserved: int, actual: int) -> None:
        """Commit actual token usage, releasing the reservation."""
        async with self._lock:
            self._reserved = max(0, self._reserved - reserved)
            self._used += actual

    async def release(self, reserved: int) -> None:
        """Release a reservation without using tokens (e.g., on error)."""
        async with self._lock:
            self._reserved = max(0, self._reserved - reserved)

    def is_exhausted(self) -> bool:
        if self.max_tokens is None:
            return False
        return self._used >= self.max_tokens
