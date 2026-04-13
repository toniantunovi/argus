"""Hypothesis models for Layer 1."""
from __future__ import annotations

from pydantic import BaseModel, Field

from argus.models.core import Severity, SignalCategory


class Hypothesis(BaseModel):
    """A single vulnerability hypothesis from Layer 1."""
    title: str
    description: str
    severity: Severity
    category: SignalCategory
    affected_lines: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    attack_scenario: str = ""

class HypothesisResponse(BaseModel):
    """LLM response for hypothesis generation."""
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    analysis_notes: str = ""

class ConfidenceGate:
    """Gate hypotheses by confidence threshold."""
    def __init__(self, promote_threshold: float = 0.7, batch_threshold: float = 0.4):
        self.promote_threshold = promote_threshold
        self.batch_threshold = batch_threshold

    def classify(self, hypothesis: Hypothesis) -> str:
        """Classify hypothesis: 'promote', 'batch', or 'suppress'."""
        if hypothesis.confidence >= self.promote_threshold:
            return "promote"
        elif hypothesis.confidence >= self.batch_threshold:
            return "batch"
        return "suppress"
