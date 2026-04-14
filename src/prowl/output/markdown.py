"""Markdown report output — detailed, reproducible scan results."""
from __future__ import annotations

from datetime import timezone

from prowl.models.finding import Finding
from prowl.models.output import Report

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render_markdown(report: Report) -> str:
    """Render a full scan report as Markdown."""
    sections: list[str] = []

    sections.append(_render_header(report))
    sections.append(_render_summary_table(report))

    if report.findings:
        sections.append(_render_findings(report))

    if report.chains:
        sections.append(_render_chains(report))

    sections.append(_render_footer(report))

    return "\n\n".join(sections) + "\n"


def _render_header(report: Report) -> str:
    p = report.scan_progress
    lines = [
        "# Prowl Scan Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Status** | `{p.status.value}` |",
        f"| **Targets** | {p.targets_scanned} / {p.targets_total} scanned |",
    ]
    if p.wall_time_seconds:
        lines.append(f"| **Duration** | {p.wall_time_seconds:.1f}s |")
    if p.budget.tokens_used:
        lines.append(f"| **Tokens used** | {p.budget.tokens_used:,} |")
    if p.started_at:
        ts = p.started_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        lines.append(f"| **Started** | {ts.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    lines.append(f"| **Findings** | {len(report.findings)} |")

    attempted = sum(1 for f in report.findings if f.validation_attempted)
    validated = sum(1 for f in report.findings if f.poc_validated)
    if attempted:
        lines.append(f"| **Validation attempted** | {attempted} |")
        lines.append(f"| **PoC validated** | {validated} |")
        failed = sum(1 for f in report.findings if f.validation_attempted and f.validation_method == "failed")
        skipped = sum(1 for f in report.findings if f.validation_attempted and f.validation_method == "skipped")
        if failed:
            lines.append(f"| **Validation failed** | {failed} |")
        if skipped:
            lines.append(f"| **Validation skipped** | {skipped} |")

    return "\n".join(lines)


def _render_summary_table(report: Report) -> str:
    counts = report.finding_count_by_severity
    if not counts:
        return "## Summary\n\nNo findings."

    lines = [
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count > 0:
            lines.append(f"| **{sev.upper()}** | {count} |")

    return "\n".join(lines)


def _render_findings(report: Report) -> str:
    def _severity_key(f: Finding) -> int:
        return SEVERITY_ORDER.index(f.severity.value) if f.severity.value in SEVERITY_ORDER else len(SEVERITY_ORDER)

    validated = sorted([f for f in report.findings if f.poc_validated], key=_severity_key)
    other = sorted([f for f in report.findings if not f.poc_validated], key=_severity_key)

    sections: list[str] = []
    idx = 1

    if validated:
        sections.append("## Validated Findings")
        for finding in validated:
            sections.append(_render_finding(idx, finding))
            idx += 1

    if other:
        sections.append("## Other Findings")
        for finding in other:
            sections.append(_render_finding(idx, finding))
            idx += 1

    return "\n\n".join(sections)


def _render_finding(index: int, f: Finding) -> str:
    sev = SEVERITY_EMOJI.get(f.severity.value, f.severity.value.upper())
    lines = [
        f"### {index}. [{sev}] {f.title}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **ID** | `{f.finding_id}` |",
        f"| **Stable ID** | `{f.stable_id}` |",
        f"| **Category** | {f.category.value} |",
        f"| **Classification** | {f.classification.value} |",
        f"| **Confidence** | {f.confidence:.0%} |",
        f"| **File** | `{f.file_path}:{f.start_line}-{f.end_line}` |",
        f"| **Function** | `{f.function_name}` |",
    ]

    if f.poc_validated:
        lines.append(f"| **PoC status** | VALIDATED ({f.validation_method or 'confirmed'}) |")
        lines.append(f"| **Iterations** | {f.iterations_used} |")
    elif f.validation_method == "partial":
        lines.append("| **PoC status** | PARTIAL |")
    elif f.validation_method == "failed":
        lines.append("| **PoC status** | FAILED |")
    elif f.validation_method == "skipped":
        lines.append("| **PoC status** | SKIPPED |")

    if f.chain_id:
        chain_sev = f.chain_severity.value if f.chain_severity else "N/A"
        lines.append(f"| **Attack chain** | `{f.chain_id}` (severity: {chain_sev}) |")

    # Description
    if f.description:
        lines.append("")
        lines.append("#### Description")
        lines.append("")
        lines.append(f"{f.description}")

    # Attack scenario
    if f.attack_scenario:
        lines.append("")
        lines.append("#### Attack Scenario")
        lines.append("")
        lines.append(f"{f.attack_scenario}")

    # Reasoning
    if f.reasoning:
        lines.append("")
        lines.append("#### Analysis")
        lines.append("")
        lines.append(f"{f.reasoning}")

    # PoC code — always include when available, even for failed/partial attempts
    if f.poc_code:
        lang = _guess_poc_language(f)
        lines.append("")
        if f.poc_validated:
            lines.append("#### Test Script")
        elif f.validation_method == "partial":
            lines.append("#### Test Script (partial — not fully confirmed)")
        else:
            lines.append("#### Test Script (unconfirmed)")
        lines.append("")
        lines.append(_reproduction_instructions(f))
        lines.append("")
        lines.append(f"```{lang}")
        lines.append(f.poc_code.rstrip())
        lines.append("```")

    # Sanitizer output
    if f.sanitizer_output:
        lines.append("")
        lines.append("#### Sanitizer Output")
        lines.append("")
        san = f.sanitizer_output
        if isinstance(san, dict):
            if san.get("sanitizer"):
                lines.append(f"**Sanitizer:** {san['sanitizer']}")
            if san.get("type"):
                lines.append(f"**Violation type:** {san['type']}")
            if san.get("details"):
                lines.append("")
                lines.append("```")
                lines.append(str(san["details"]).rstrip())
                lines.append("```")
        else:
            lines.append(f"```\n{san}\n```")

    # Execution output (stdout/stderr from validation) — show for all attempted findings
    if f.validation_stdout:
        lines.append("")
        lines.append("#### Execution Output")
        lines.append("")
        lines.append("```")
        lines.append(f.validation_stdout.rstrip())
        lines.append("```")
    if f.validation_stderr and f.validation_attempted:
        lines.append("")
        lines.append("#### Execution Output (stderr)")
        lines.append("")
        lines.append("```")
        lines.append(f.validation_stderr.rstrip())
        lines.append("```")

    # Patch
    if f.patch_code:
        lang = _guess_language(f)
        lines.append("")
        lines.append("#### Suggested Patch")
        lines.append("")
        lines.append(f"```{lang}")
        lines.append(f.patch_code.rstrip())
        lines.append("```")

    return "\n".join(lines)


def _reproduction_instructions(f: Finding) -> str:
    """Build step-by-step reproduction instructions for the test script.

    Layer 3 validation builds the real project and runs the actual binary/server
    with crafted input — it never generates standalone PoC code.  The artifact
    stored in ``poc_code`` is the test script that was executed inside the
    Docker sandbox.
    """
    steps = ["**How to reproduce:**", ""]
    if f.category.value == "memory":
        steps.extend([
            "1. Save the test script below as `test.sh` in the project root.",
            "2. Build the project from source with AddressSanitizer instrumentation:",
            "   ```",
            "   CFLAGS=\"-fsanitize=address,undefined -fno-omit-frame-pointer -g\" ./configure && make -j$(nproc)",
            "   ```",
            "3. Run `bash test.sh` and observe the ASAN violation in stderr.",
        ])
    elif f.category.value in ("injection", "data_access", "auth", "input"):
        steps.extend([
            "1. Save the test script below as `test.sh` (or `test.py`) in the project root.",
            "2. Start the application server (e.g. `flask run`, `npm start`).",
            "3. Run the test script — it sends crafted requests to the running server.",
            "4. Observe the `ARGUS_VALIDATED` marker in stdout confirming the vulnerability.",
        ])
    else:
        steps.extend([
            "1. Save the test script below as `test.sh` in the project root.",
            "2. Build the project from source.",
            "3. Run the test script against the built binary and observe the output.",
        ])
    return "\n".join(steps)


def _guess_poc_language(f: Finding) -> str:
    """Guess code-fence language for the PoC / test script.

    The PoC is a test script produced by Layer 3, not standalone source in the
    same language as the target.  Detect the actual content type first (shebang,
    Python imports, etc.) before falling back to the source-file extension.
    """
    code = (f.poc_code or "").lstrip()
    if code.startswith("#!/bin/bash") or code.startswith("#!/bin/sh") or code.startswith("#!/usr/bin/env bash"):
        return "bash"
    if code.startswith("#!/usr/bin/env python") or code.startswith("#!/usr/bin/python"):
        return "python"
    if code.startswith("import ") or code.startswith("from "):
        return "python"
    # Fall back to source-file extension (useful for patches, not PoCs).
    path = f.file_path.lower()
    if path.endswith((".c", ".h")):
        return "c"
    if path.endswith((".cpp", ".cc", ".cxx", ".hpp")):
        return "cpp"
    if path.endswith(".py"):
        return "python"
    if path.endswith((".js", ".mjs")):
        return "javascript"
    if path.endswith((".ts", ".tsx")):
        return "typescript"
    if path.endswith(".go"):
        return "go"
    if path.endswith((".java",)):
        return "java"
    if path.endswith((".rs",)):
        return "rust"
    return ""


def _guess_language(f: Finding) -> str:
    """Guess language from source-file extension (for patches, not PoCs)."""
    path = f.file_path.lower()
    if path.endswith((".c", ".h")):
        return "c"
    if path.endswith((".cpp", ".cc", ".cxx", ".hpp")):
        return "cpp"
    if path.endswith(".py"):
        return "python"
    if path.endswith((".js", ".mjs")):
        return "javascript"
    if path.endswith((".ts", ".tsx")):
        return "typescript"
    if path.endswith(".go"):
        return "go"
    if path.endswith((".java",)):
        return "java"
    if path.endswith((".rs",)):
        return "rust"
    return ""


def _render_chains(report: Report) -> str:
    lines = ["## Attack Chains"]
    for chain in report.chains:
        chain_id = chain.get("chain_id", "unknown")
        lines.append(f"\n### Chain: `{chain_id}`")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Type** | {chain.get('chain_type', 'unknown')} |")
        lines.append(f"| **Severity** | {chain.get('combined_severity', 'unknown')} |")
        if chain.get("description"):
            lines.append("")
            lines.append(chain["description"])
        if chain.get("finding_ids"):
            lines.append("")
            lines.append("**Findings in this chain:**")
            for fid in chain["finding_ids"]:
                lines.append(f"- `{fid}`")
    return "\n".join(lines)


def _render_footer(report: Report) -> str:
    lines = ["---", "", "*Report generated by [Prowl](https://github.com/prowl)*"]
    return "\n".join(lines)
