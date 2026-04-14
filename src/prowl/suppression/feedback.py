"""Feed suppression reasons into context builder."""
from __future__ import annotations

from prowl.suppression.manager import SuppressionManager


def get_suppression_context(manager: SuppressionManager, function_name: str, file_path: str) -> str | None:
    """Get suppression context for a function to include in future scans.

    If this function was previously suppressed, return the reason so the context
    builder can include relevant middleware/validation that was missing from context.
    """
    reasons = manager.get_suppression_reasons(function_name, file_path)
    if not reasons:
        return None

    parts = ["Previous suppressions for this function:"]
    for reason in reasons:
        parts.append(f"  - {reason}")
    parts.append("Consider whether these suppressions still apply given the current code.")
    return "\n".join(parts)
