"""Prompt templates for Layer 2 triage and chain analysis."""
from __future__ import annotations

from argus.models.context import FindingContext
from argus.models.finding import Finding

TRIAGE_SYSTEM_PROMPT = """You are an expert security researcher performing vulnerability triage. Given a hypothesis and extended context, classify the vulnerability.

You MUST classify into one of:
- "exploitable": The vulnerability is reachable and no mitigation blocks it.
- "mitigated": A real bug exists but existing defenses prevent exploitation.
- "false_positive": The hypothesis was wrong.
- "uncertain": Insufficient context to determine exploitability.

IMPORTANT: Respond with ONLY a valid JSON object. No explanations, no markdown, no text before or after the JSON.

{"classification": "exploitable|mitigated|false_positive|uncertain", "severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "detailed reasoning", "attack_path": "how an attacker would exploit this", "mitigations_found": ["list of mitigations that affect exploitability"]}
"""

BATCH_TRIAGE_SYSTEM_PROMPT = """You are an expert security researcher. You are given multiple vulnerability hypotheses from the same area of code. Evaluate each one.

IMPORTANT: Respond with ONLY a valid JSON array. No explanations, no markdown, no text before or after the JSON.

[{"title": "hypothesis title", "classification": "exploitable|mitigated|false_positive|uncertain", "severity": "critical|high|medium|low|info", "confidence": 0.0-1.0, "reasoning": "explanation"}]
"""

CHAIN_SYSTEM_PROMPT = """You are an expert security researcher evaluating whether multiple vulnerabilities combine into a more severe attack chain.

Consider whether the findings:
1. Allow privilege escalation beyond any single finding
2. Enable sandbox escape
3. Create an authentication/authorization bypass path
4. Achieve remote code execution through combination
5. Bypass mitigations that block individual findings

IMPORTANT: Respond with ONLY a valid JSON object. No explanations, no markdown, no text before or after the JSON.

{"is_chain": true, "chain_type": "privilege_chain|sandbox_escape|auth_bypass_chain|rce_chain|mitigation_bypass|null", "combined_severity": "critical|high|medium|low", "description": "how the findings combine", "reasoning": "detailed analysis"}
"""


def build_triage_prompt(context: FindingContext) -> str:
    """Build triage prompt for a single hypothesis."""
    parts = [
        f"## Vulnerability Hypothesis: {context.hypothesis_title}",
        f"Category: {context.hypothesis_category.value}",
        f"Description: {context.hypothesis_description}",
        "\n### Vulnerable Function (Sink):",
        f"File: {context.target_file}, Lines: {context.target_lines[0]}-{context.target_lines[1]}",
        f"```\n{context.sink_code}\n```",
    ]
    if context.source_code:
        parts.append(f"\n### Entry Point (Source):\n```\n{context.source_code}\n```")
    if context.call_chain:
        parts.append("\n### Call Chain (source -> sink):")
        for i, step in enumerate(context.call_chain):
            parts.append(f"Step {i + 1}:\n```\n{step}\n```")
    if context.sanitizers_in_path:
        parts.append(f"\n### Sanitizers in Path: {', '.join(context.sanitizers_in_path)}")
    if context.middleware:
        parts.append(f"\n### Middleware: {', '.join(context.middleware)}")
    if context.mitigations:
        parts.append(f"\n### Mitigations: {', '.join(context.mitigations)}")
    if context.framework:
        parts.append(f"\n### Framework: {context.framework}")
    if context.evaluation_rubric:
        parts.append(f"\n### Evaluation Rubric:\n{context.evaluation_rubric}")
    parts.append("\nClassify this vulnerability hypothesis.")
    return "\n".join(parts)


def build_batch_triage_prompt(contexts: list[FindingContext]) -> str:
    """Build batch triage prompt for multiple hypotheses from same area."""
    parts = ["## Batch Vulnerability Triage\n"]
    parts.append(
        f"The following {len(contexts)} hypotheses are from related code. Evaluate each one.\n"
    )
    for i, ctx in enumerate(contexts):
        parts.append(f"### Hypothesis {i + 1}: {ctx.hypothesis_title}")
        parts.append(f"Category: {ctx.hypothesis_category.value}")
        parts.append(f"Description: {ctx.hypothesis_description}")
        parts.append(f"Function: {ctx.target_name} in {ctx.target_file}")
        parts.append(f"```\n{ctx.target_source}\n```\n")
    return "\n".join(parts)


def build_chain_prompt(findings: list[Finding], rubric: str) -> str:
    """Build chain evaluation prompt."""
    parts = ["## Chain Evaluation\n"]
    parts.append(
        f"Evaluate whether these {len(findings)} findings combine into an attack chain.\n"
    )
    for i, finding in enumerate(findings):
        parts.append(f"### Finding {i + 1}: {finding.title}")
        parts.append(f"Severity: {finding.severity.value}, Category: {finding.category.value}")
        parts.append(f"Description: {finding.description}")
        parts.append(f"File: {finding.file_path}:{finding.start_line}")
        if finding.attack_scenario:
            parts.append(f"Attack scenario: {finding.attack_scenario}")
        parts.append("")
    if rubric:
        parts.append(f"### Chain Rules:\n{rubric}")
    return "\n".join(parts)
