"""Token budget enforcement with priority rules."""
from __future__ import annotations


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def trim_to_budget(sections: dict[str, str], budget: int = 4000) -> dict[str, str]:
    """Trim context sections to fit within token budget.

    Priority order (highest first):
    1. target_source (sink code) - never trimmed
    2. detection_rubric / evaluation_rubric / exploit_rubric
    3. source_code (entry point)
    4. callers[0] (immediate caller)
    5. sanitizers_in_path
    6. callees
    7. callers[1:] (further callers)
    8. type_definitions
    9. framework_context
    10. imports
    """
    PRIORITY = [
        "target_source", "detection_rubric", "evaluation_rubric", "exploit_rubric",
        "source_code", "sink_code", "callers_0", "sanitizers_in_path",
        "callees", "callers_rest", "type_definitions", "framework_context",
        "imports", "iteration_history", "coverage_data",
    ]

    result = {}
    used = 0

    for key in PRIORITY:
        if key not in sections:
            continue
        text = sections[key]
        tokens = estimate_tokens(text)
        if used + tokens <= budget:
            result[key] = text
            used += tokens
        else:
            remaining = budget - used
            if remaining > 100:  # only include if we can fit meaningful content
                chars = remaining * 4
                result[key] = text[:chars] + "\n... [trimmed]"
                used = budget
            break

    return result
