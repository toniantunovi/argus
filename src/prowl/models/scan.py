from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    RESUMED = "resumed"

class SkipReasons(BaseModel):
    parse_failure: int = 0
    llm_error: int = 0
    budget_exhausted: int = 0
    sandbox_failure: int = 0

class BudgetState(BaseModel):
    tokens_used: int = 0
    estimated_cost_usd: float = 0.0
    max_tokens: int | None = None
    max_cost: float | None = None
    layer3_budget_fraction: float = 0.4

    @property
    def tokens_remaining(self) -> int | None:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self.tokens_used)

    def can_spend(self, tokens: int) -> bool:
        if self.max_tokens is None:
            return True
        return self.tokens_used + tokens <= self.max_tokens

class ScanProgress(BaseModel):
    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    targets_total: int = 0
    targets_scanned: int = 0
    targets_skipped: int = 0
    skip_reasons: SkipReasons = Field(default_factory=SkipReasons)
    layers_completed: list[str] = Field(default_factory=list)
    budget: BudgetState = Field(default_factory=BudgetState)
    wall_time_seconds: float = 0.0
    auto_excluded_paths: int = 0
    interaction_targets_found: int = 0
    cross_language_boundaries: list[str] = Field(default_factory=list)
    bootstrap_tier: dict[str, int] = Field(default_factory=lambda: {"tier1": 0, "tier2": 0, "tier3": 0, "tier4_fallback": 0})
    resumed_from: str | None = None

class ScanState(BaseModel):
    progress: ScanProgress
    recon_complete: bool = False
    hypothesis_complete: list[str] = Field(default_factory=list)  # completed target IDs
    triage_complete: list[str] = Field(default_factory=list)
    validation_complete: list[str] = Field(default_factory=list)
