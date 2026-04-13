from __future__ import annotations

import enum
from pathlib import Path

from pydantic import BaseModel, Field


class SignalCategory(str, enum.Enum):
    AUTH = "auth"
    DATA_ACCESS = "data_access"
    INPUT = "input"
    CRYPTO = "crypto"
    FINANCIAL = "financial"
    PRIVILEGE = "privilege"
    MEMORY = "memory"
    INJECTION = "injection"
    CONCURRENCY = "concurrency"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RubricTier(str, enum.Enum):
    CONSERVATIVE = "conservative"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"

class ProjectType(str, enum.Enum):
    APPLICATION = "application"
    LIBRARY = "library"
    MIXED = "mixed"
    AUTO = "auto"

class RiskSignal(BaseModel):
    category: SignalCategory
    name: str
    description: str
    weight: float
    line_number: int | None = None
    pattern: str | None = None  # the matched pattern

class Function(BaseModel):
    name: str
    file_path: Path
    start_line: int
    end_line: int
    source: str
    language: str
    parameters: list[str] = Field(default_factory=list)
    return_type: str | None = None
    decorators: list[str] = Field(default_factory=list)
    is_public: bool = True
    is_entry_point: bool = False
    # Populated during analysis
    signals: list[RiskSignal] = Field(default_factory=list)
    complexity: int = 0
    callers: list[str] = Field(default_factory=list)  # function identifiers
    callees: list[str] = Field(default_factory=list)

    @property
    def identifier(self) -> str:
        return f"{self.file_path}::{self.name}"

class VulnerabilityScore(BaseModel):
    function_id: str
    signal_score: float = 0.0
    complexity_modifier: float = 0.0
    exposure_modifier: float = 0.0

    @property
    def total(self) -> float:
        return self.signal_score + self.complexity_modifier + self.exposure_modifier

    @property
    def rubric_tier(self) -> RubricTier:
        t = self.total
        if t >= 4.0:
            return RubricTier.AGGRESSIVE
        elif t >= 2.5:
            return RubricTier.STANDARD
        else:
            return RubricTier.CONSERVATIVE

class Target(BaseModel):
    function: Function
    score: VulnerabilityScore
    priority_rank: int = 0
    interaction_group_id: str | None = None  # if part of an interaction target

    @property
    def should_skip(self) -> bool:
        return self.score.total < 1.0
