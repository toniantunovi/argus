"""Prompt templates for Layer 3 patch generation."""
from __future__ import annotations

from prowl.models.context import ExploitContext

PATCH_SYSTEM_PROMPT = """You are an expert security engineer generating minimal patches to fix vulnerabilities. Generate a patch that:

1. Fixes the specific vulnerability without changing behavior for non-adversarial inputs.
2. Is minimal -- change as few lines as possible.
3. Uses the language's idiomatic security patterns (parameterized queries, bounds checks, etc.).

Respond with ONLY the patched function source code, no explanation.
"""


def build_patch_prompt(context: ExploitContext, poc_code: str) -> str:
    """Build the patch generation prompt."""
    parts = [
        "## Vulnerability to Fix",
        f"Category: {context.finding_category.value}",
        f"Severity: {context.finding_severity}",
        f"\n### Vulnerable Function:\n```\n{context.target_source}\n```",
        f"\n### Working PoC (must fail after patch):\n```\n{poc_code}\n```",
    ]
    if context.exploit_rubric:
        parts.append(f"\n### Remediation Guidance:\n{context.exploit_rubric}")
    parts.append("\nGenerate the patched function. Return ONLY the corrected source code.")
    return "\n".join(parts)
