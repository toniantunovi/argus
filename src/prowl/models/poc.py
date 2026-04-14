"""PoC and validation models for Layer 3."""
from __future__ import annotations

import enum

from pydantic import BaseModel, Field


class ValidationStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"

class PoC(BaseModel):
    """Generated proof-of-concept."""
    code: str
    language: str
    description: str = ""
    setup_instructions: str = ""

class ValidationResult(BaseModel):
    """Result of PoC execution in sandbox."""
    status: ValidationStatus
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    http_response: str | None = None
    sanitizer_output: str | None = None
    success_evidence: str = ""
    failure_reason: str = ""

class IterationState(BaseModel):
    """Track state across PoC iterations."""
    iteration: int = 0
    max_iterations: int = 3
    attempts: list[dict] = Field(default_factory=list)  # history of what was tried
    current_poc: PoC | None = None
    best_result: ValidationResult | None = None

    @property
    def budget_remaining(self) -> int:
        return max(0, self.max_iterations - self.iteration)

    @property
    def is_exhausted(self) -> bool:
        return self.iteration >= self.max_iterations

class PatchResult(BaseModel):
    """Result of patch generation and validation."""
    patch_code: str
    compiles: bool = False
    poc_fails: bool = False
    tests_pass: bool = False

    @property
    def is_valid(self) -> bool:
        return self.compiles and self.poc_fails and self.tests_pass
