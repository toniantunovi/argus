"""Concurrency primitives for bounded parallelism."""
from __future__ import annotations

import anyio

from prowl.config import ConcurrencyConfig


class ConcurrencyManager:
    """Manages capacity limiters for each pipeline layer."""

    def __init__(self, config: ConcurrencyConfig | None = None):
        if config is None:
            config = ConcurrencyConfig()
        self.hypothesis_limiter = anyio.CapacityLimiter(config.max_concurrent_hypotheses)
        self.triage_limiter = anyio.CapacityLimiter(config.max_concurrent_triage)
        self.validation_limiter = anyio.CapacityLimiter(config.max_concurrent_validations)
