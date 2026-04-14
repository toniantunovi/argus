"""AI-consumable output format with narratives."""
from __future__ import annotations

import json

from prowl.models.finding import Finding
from prowl.models.output import AIFinding, Report


def render_ai(report: Report) -> str:
    """Render report in AI-consumable format."""
    ai_findings = []
    for finding in report.findings:
        ai_finding = AIFinding(
            id=finding.finding_id,
            severity=finding.severity.value,
            category=finding.category.value,
            title=finding.title,
            narrative=_build_narrative(finding),
            affected_function={
                "file": finding.file_path,
                "name": finding.function_name,
                "lines": [finding.start_line, finding.end_line],
            },
            entry_point=finding.attack_scenario[:200] if finding.attack_scenario else "",
            remediation=_build_remediation(finding),
            poc_validated=finding.poc_validated,
            confidence=finding.confidence,
        )
        ai_findings.append(ai_finding.model_dump())

    output = {
        "format": "ai",
        "scan_status": report.scan_progress.status.value,
        "findings": ai_findings,
        "chains": report.chains,
    }
    return json.dumps(output, indent=2)


def _build_narrative(finding: Finding) -> str:
    """Build natural-language attack narrative."""
    parts = []
    parts.append(f"The function {finding.function_name} at {finding.file_path}:{finding.start_line}")
    if finding.description:
        parts.append(finding.description)
    if finding.attack_scenario:
        parts.append(f"An attacker could: {finding.attack_scenario}")
    if finding.poc_validated:
        parts.append("This vulnerability has been confirmed with a working proof-of-concept.")
    return " ".join(parts)


def _build_remediation(finding: Finding) -> dict:
    """Build remediation guidance."""
    categories_to_fix = {
        "auth": "add_authorization_check",
        "data_access": "use_parameterized_query",
        "injection": "use_parameterized_input",
        "memory": "add_bounds_check",
        "crypto": "use_strong_algorithm",
        "input": "add_input_validation",
        "concurrency": "add_synchronization",
        "financial": "add_state_validation",
        "privilege": "fix_privilege_handling",
    }
    return {
        "category": categories_to_fix.get(finding.category.value, "fix_vulnerability"),
        "description": f"Fix the {finding.category.value} vulnerability in {finding.function_name}.",
        "patch_available": finding.patch_code is not None,
    }
