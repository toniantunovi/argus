"""Context models for the 3 analysis layers."""
from __future__ import annotations

from pydantic import BaseModel, Field

from prowl.models.core import RubricTier, SignalCategory


class FunctionContext(BaseModel):
    """Layer 1 context (~4000 tokens)."""
    target_source: str
    target_name: str
    target_file: str
    target_lines: tuple[int, int]
    language: str
    callers: list[str] = Field(default_factory=list)  # source code of callers
    callees: list[str] = Field(default_factory=list)
    type_definitions: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    framework_context: str | None = None
    detection_rubric: str = ""
    risk_categories: list[SignalCategory] = Field(default_factory=list)
    rubric_tier: RubricTier = RubricTier.STANDARD


class FindingContext(BaseModel):
    """Layer 2 context (extended triage context)."""
    # Everything from FunctionContext
    target_source: str
    target_name: str
    target_file: str
    target_lines: tuple[int, int]
    language: str
    # Layer 2 specific
    sink_code: str = ""
    source_code: str = ""  # entry point source
    call_chain: list[str] = Field(default_factory=list)
    type_definitions: list[str] = Field(default_factory=list)
    framework: str | None = None
    middleware: list[str] = Field(default_factory=list)
    sanitizers_in_path: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    evaluation_rubric: str = ""
    hypothesis_title: str = ""
    hypothesis_description: str = ""
    hypothesis_category: SignalCategory = SignalCategory.AUTH


class ExploitContext(BaseModel):
    """Layer 3 context (~8000 tokens)."""
    # Base context
    target_source: str
    target_name: str
    target_file: str
    target_lines: tuple[int, int]
    language: str
    # Finding context
    sink_code: str = ""
    source_code: str = ""
    call_chain: list[str] = Field(default_factory=list)
    type_definitions: list[str] = Field(default_factory=list)
    framework: str | None = None
    sanitizers_in_path: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    # Exploit specific
    exploit_rubric: str = ""
    iteration_history: list[str] = Field(default_factory=list)  # previous attempt summaries
    coverage_data: str | None = None
    sanitizer_traces: list[str] = Field(default_factory=list)
    finding_severity: str = "high"
    finding_category: SignalCategory = SignalCategory.AUTH
    build_system_hint: str | None = None
    server_indicators: list[str] = Field(default_factory=list)
