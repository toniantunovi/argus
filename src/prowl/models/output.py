"""Output format models."""
from __future__ import annotations

from pydantic import BaseModel, Field

from prowl.models.finding import Finding
from prowl.models.scan import ScanProgress


class Report(BaseModel):
    """Complete scan report."""
    scan_progress: ScanProgress
    findings: list[Finding] = Field(default_factory=list)
    chains: list[dict] = Field(default_factory=list)

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

class SARIFResult(BaseModel):
    """SARIF 2.1.0 result representation."""
    ruleId: str
    level: str  # error, warning, note
    message: dict
    locations: list[dict] = Field(default_factory=list)
    relatedLocations: list[dict] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)

class AIFinding(BaseModel):
    """AI-consumable finding format."""
    id: str
    severity: str
    category: str
    title: str
    narrative: str
    affected_function: dict
    entry_point: str = ""
    remediation: dict = Field(default_factory=dict)
    poc_validated: bool = False
    confidence: float = 0.0
