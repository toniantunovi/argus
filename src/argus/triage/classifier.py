"""Classification helpers for triage results."""
from __future__ import annotations

from argus.models.finding import Classification, Finding


def should_validate(finding: Finding, severity_gate: str = "high") -> bool:
    """Determine if a finding should proceed to Layer 3 validation.

    A finding is sent to validation when it is classified as exploitable or
    uncertain *and* its severity meets the gate threshold.  False positives
    and mitigated findings are never validated.
    """
    if finding.classification == Classification.FALSE_POSITIVE:
        return False
    if finding.classification == Classification.MITIGATED:
        return False  # reported at lower severity, no PoC needed

    gate_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finding_rank = gate_order.get(finding.severity.value, 4)
    gate_rank = gate_order.get(severity_gate, 1)

    if finding_rank > gate_rank:
        return False

    return finding.classification in (
        Classification.EXPLOITABLE,
        Classification.UNCERTAIN,
    )


def filter_for_validation(
    findings: list[Finding], severity_gate: str = "high"
) -> list[Finding]:
    """Filter findings that should proceed to Layer 3."""
    return [f for f in findings if should_validate(f, severity_gate)]
