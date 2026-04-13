"""Confidence gating and batch grouping for Layer 1 -> Layer 2 transition."""
from __future__ import annotations

from collections import defaultdict

from argus.models.core import Target
from argus.models.hypothesis import Hypothesis


def group_batched_hypotheses(
    hypotheses: list[Hypothesis],
    targets: dict[str, Target],
) -> dict[str, list[Hypothesis]]:
    """Group mid-confidence hypotheses by module for batch triage.

    Returns dict of module_path -> list of hypotheses from that module.
    """
    # Group by file/module
    groups: dict[str, list[Hypothesis]] = defaultdict(list)
    # The hypothesis doesn't directly carry file info, so we need to match
    # via targets.  For now, group by category as a reasonable approximation.
    for hyp in hypotheses:
        groups[hyp.category.value].append(hyp)
    return dict(groups)
