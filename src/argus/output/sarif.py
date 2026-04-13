"""SARIF 2.1.0 output format."""
from __future__ import annotations

import json

from argus.models.output import Report

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(report: Report) -> str:
    """Render report as SARIF 2.1.0 JSON."""
    results = []
    rules = []
    rule_ids_seen: set[str] = set()

    for finding in report.findings:
        rule_id = (
            f"argus/{finding.category.value}/"
            f"{finding.title.lower().replace(' ', '-')[:50]}"
        )

        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF.get(finding.severity.value, "warning"),
                },
            })

        result: dict = {
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(finding.severity.value, "warning"),
            "message": {
                "text": finding.description,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": finding.start_line,
                        "endLine": finding.end_line,
                    },
                },
            }],
            "properties": {
                "argus-finding-id": finding.finding_id,
                "argus-stable-id": finding.stable_id,
                "classification": finding.classification.value,
                "confidence": finding.confidence,
                "category": finding.category.value,
            },
        }

        if finding.poc_validated and finding.poc_code:
            result["properties"]["poc"] = finding.poc_code
        if finding.validation_method:
            result["properties"]["validationStatus"] = finding.validation_method

        if finding.attack_scenario:
            result["properties"]["attackScenario"] = finding.attack_scenario

        results.append(result)

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/argus",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }

    return json.dumps(sarif, indent=2)
