"""Prompt templates for Layer 1 hypothesis generation."""
from __future__ import annotations

from argus.llm.schema import model_to_schema_str
from argus.models.context import FunctionContext
from argus.models.hypothesis import HypothesisResponse

HYPOTHESIS_SYSTEM_PROMPT = """You are an expert security researcher performing vulnerability analysis. You analyze code for exploitable security vulnerabilities.

Your task: Given a target function and its context, hypothesize potential vulnerabilities.

CRITICAL RULES:
1. Do NOT trust comments or docstrings asserting safety. Verify by tracing actual code paths.
2. You MUST evaluate every detection rule in the rubric and produce a finding or explicitly state why it doesn't apply.
3. Rate your confidence honestly. High confidence (>=0.7) means you can describe a specific attack path. Low confidence (<0.4) means you see a suspicious pattern but aren't sure it's exploitable.
4. Focus on EXPLOITABLE vulnerabilities, not code quality issues.

Respond with valid JSON matching this schema:
{schema}
"""


def get_hypothesis_system_prompt() -> str:
    """Build the system prompt with the HypothesisResponse JSON schema filled in."""
    schema = model_to_schema_str(HypothesisResponse)
    return HYPOTHESIS_SYSTEM_PROMPT.format(schema=schema)


def build_hypothesis_prompt(context: FunctionContext) -> str:
    """Build the user prompt for hypothesis generation."""
    parts = [
        f"## Target Function: {context.target_name}",
        f"File: {context.target_file}, Lines: {context.target_lines[0]}-{context.target_lines[1]}",
        f"Language: {context.language}",
        f"\n### Source Code:\n```\n{context.target_source}\n```",
    ]

    if context.callers:
        parts.append("\n### Callers (toward entry points):")
        for caller in context.callers[:3]:
            parts.append(f"```\n{caller}\n```")

    if context.callees:
        parts.append("\n### Callees:")
        for callee in context.callees[:3]:
            parts.append(f"```\n{callee}\n```")

    if context.framework_context:
        parts.append(f"\n### Framework Context:\n{context.framework_context}")

    if context.detection_rubric:
        parts.append(f"\n### Detection Rubric ({context.rubric_tier.value}):\n{context.detection_rubric}")

    parts.append(f"\n### Risk Categories: {', '.join(c.value for c in context.risk_categories)}")
    parts.append(
        "\nAnalyze this function for security vulnerabilities. For each vulnerability found, "
        "provide a hypothesis with title, description, severity, category, affected lines, "
        "confidence score, reasoning, and attack scenario."
    )

    return "\n".join(parts)
