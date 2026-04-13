"""Prompt templates for Layer 3 PoC generation and patch generation."""
from __future__ import annotations

from argus.models.context import ExploitContext

POC_SYSTEM_PROMPT = """You are an expert security researcher generating proof-of-concept exploits. Generate working PoC code that demonstrates the vulnerability.

RULES:
1. The PoC must be self-contained and executable.
2. For web vulnerabilities: use the requests library (Python) or fetch (Node.js) to make HTTP requests to localhost.
3. For memory bugs: craft input that triggers the sanitizer (ASAN/UBSAN).
4. For injection: craft input that demonstrates the injection with observable side effects.
5. Print clear evidence of success to stdout.
6. Do NOT import libraries that aren't available in the sandbox.

RESPONSE FORMAT — you MUST respond with EXACTLY this structure, nothing else:
1. A fenced code block with the language tag containing the PoC source code.
2. Followed by a JSON object with metadata (do NOT put the code in the JSON).

Example:

```c
#include <stdio.h>
int main() { return 0; }
```
{"language": "c", "description": "what this PoC does", "setup_instructions": "any setup needed"}
"""

PATCH_SYSTEM_PROMPT = """You are an expert security engineer generating minimal patches to fix vulnerabilities. Generate a patch that:

1. Fixes the specific vulnerability without changing behavior for non-adversarial inputs.
2. Is minimal -- change as few lines as possible.
3. Uses the language's idiomatic security patterns (parameterized queries, bounds checks, etc.).

Respond with ONLY the patched function source code, no explanation.
"""


def build_poc_prompt(context: ExploitContext) -> str:
    """Build the PoC generation prompt."""
    parts = [
        f"## Vulnerability: {context.finding_category.value}",
        f"Severity: {context.finding_severity}",
        f"Language: {context.language}",
        "\n### Vulnerable Function:",
        f"File: {context.target_file}, Lines: {context.target_lines[0]}-{context.target_lines[1]}",
        f"```\n{context.target_source}\n```",
    ]
    if context.source_code:
        parts.append(f"\n### Entry Point:\n```\n{context.source_code}\n```")
    if context.call_chain:
        parts.append("\n### Call Chain:")
        for step in context.call_chain[:5]:
            parts.append(f"```\n{step}\n```")
    if context.framework:
        parts.append(f"\n### Framework: {context.framework}")
    if context.exploit_rubric:
        parts.append(f"\n### Exploit Rubric:\n{context.exploit_rubric}")
    if context.iteration_history:
        parts.append("\n### Previous Attempts:")
        for attempt in context.iteration_history:
            parts.append(f"- {attempt}")
    if context.sanitizer_traces:
        parts.append("\n### Sanitizer Output from Previous Attempts:")
        for trace in context.sanitizer_traces:
            parts.append(f"```\n{trace}\n```")
    parts.append("\nGenerate a working proof-of-concept that demonstrates this vulnerability.")
    return "\n".join(parts)


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
