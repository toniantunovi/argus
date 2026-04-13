"""Rich terminal output."""
from __future__ import annotations

from argus.models.output import Report

SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def render_text(report: Report) -> str:
    """Render report as colored text for terminal."""
    lines: list[str] = []
    progress = report.scan_progress

    # Header
    lines.append("=" * 60)
    lines.append("ARGUS SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Status: {progress.status.value}")
    lines.append(f"Targets: {progress.targets_scanned}/{progress.targets_total} scanned")
    if progress.wall_time_seconds:
        lines.append(f"Time: {progress.wall_time_seconds:.1f}s")
    if progress.budget.tokens_used:
        lines.append(f"Tokens used: {progress.budget.tokens_used:,}")
    lines.append("")

    # Summary
    counts = report.finding_count_by_severity
    if counts:
        lines.append("FINDINGS SUMMARY")
        lines.append("-" * 40)
        for sev in SEVERITY_ORDER:
            count = counts.get(sev, 0)
            if count > 0:
                lines.append(f"  [{sev.upper()}] {count}")
        lines.append("")

    # Findings
    if report.findings:
        lines.append("FINDINGS")
        lines.append("-" * 40)
        sorted_findings = sorted(
            report.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
        )
        for i, finding in enumerate(sorted_findings, 1):
            lines.append(f"\n[{finding.severity.value.upper()}] #{i}: {finding.title}")
            lines.append(f"  ID: {finding.finding_id}")
            lines.append(f"  Category: {finding.category.value}")
            lines.append(f"  File: {finding.file_path}:{finding.start_line}")
            lines.append(f"  Classification: {finding.classification.value}")
            lines.append(f"  Confidence: {finding.confidence:.2f}")
            if finding.description:
                lines.append(f"  Description: {finding.description}")
            if finding.attack_scenario:
                lines.append(f"  Attack: {finding.attack_scenario}")
            if finding.poc_validated:
                lines.append(f"  PoC: VALIDATED ({finding.iterations_used} iterations)")
            elif finding.validation_method == "failed":
                lines.append("  PoC: FAILED")
            elif finding.validation_method == "skipped":
                lines.append("  PoC: SKIPPED")
            if finding.chain_id:
                chain_sev = finding.chain_severity.value if finding.chain_severity else "N/A"
                lines.append(f"  Chain: {finding.chain_id} (severity: {chain_sev})")
    else:
        lines.append("No findings.")

    # Chains
    if report.chains:
        lines.append("\n" + "=" * 40)
        lines.append("ATTACK CHAINS")
        lines.append("-" * 40)
        for chain in report.chains:
            lines.append(f"  Chain: {chain.get('chain_id', 'unknown')}")
            lines.append(f"  Type: {chain.get('chain_type', 'unknown')}")
            lines.append(f"  Severity: {chain.get('combined_severity', 'unknown')}")
            if chain.get("description"):
                lines.append(f"  Description: {chain['description']}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
