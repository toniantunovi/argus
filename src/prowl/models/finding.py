"""Finding models for Layer 2 triage."""
from __future__ import annotations

import enum
from pathlib import Path

from pydantic import BaseModel, Field

from prowl.models.core import Severity, SignalCategory


class Classification(str, enum.Enum):
    EXPLOITABLE = "exploitable"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"

class FindingId(BaseModel):
    """Human-readable finding ID."""
    category: str
    file: str
    line: int

    def __str__(self) -> str:
        return f"prowl-{self.category}-{self.file}-{self.line}"

class StableId(BaseModel):
    """Stable finding ID that survives line changes."""
    category: str
    file: str
    function_name: str

    def __str__(self) -> str:
        return f"prowl-{self.category}-{self.file}::{self.function_name}"

class Finding(BaseModel):
    """A triaged vulnerability finding."""
    finding_id: str
    stable_id: str
    title: str
    description: str
    severity: Severity
    category: SignalCategory
    classification: Classification = Classification.UNCERTAIN
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    reasoning: str = ""
    attack_scenario: str = ""
    file_path: str = ""
    function_name: str = ""
    start_line: int = 0
    end_line: int = 0
    affected_lines: list[int] = Field(default_factory=list)
    # Layer 3 results
    validation_attempted: bool = False
    poc_validated: bool = False
    validation_method: str | None = None
    poc_code: str | None = None
    patch_code: str | None = None
    iterations_used: int = 0
    validation_stdout: str | None = None
    validation_stderr: str | None = None
    sanitizer_output: dict | None = None
    validation_strategy: str | None = None
    # Chain info
    chain_id: str | None = None
    chain_severity: Severity | None = None

    @classmethod
    def from_hypothesis(cls, hyp, func) -> Finding:
        """Create a Finding from a Hypothesis and Function."""
        file_name = Path(func.file_path).name
        finding_id = f"prowl-{hyp.category.value}-{file_name}-{func.start_line}"
        stable_id = f"prowl-{hyp.category.value}-{file_name}::{func.name}"
        return cls(
            finding_id=finding_id,
            stable_id=stable_id,
            title=hyp.title,
            description=hyp.description,
            severity=hyp.severity,
            category=hyp.category,
            confidence=hyp.confidence,
            reasoning=hyp.reasoning,
            attack_scenario=hyp.attack_scenario,
            file_path=str(func.file_path),
            function_name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            affected_lines=hyp.affected_lines,
        )
