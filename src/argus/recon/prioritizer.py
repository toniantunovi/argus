"""Target ranking by vulnerability score with tiebreakers."""
from __future__ import annotations

from argus.models.core import (
    Function,
    SignalCategory,
    Target,
    VulnerabilityScore,
)
from argus.recon.call_graph import CallGraph

# Signal categories considered "dangerous" for tiebreaker 1
_DANGEROUS_CATEGORIES: frozenset[SignalCategory] = frozenset({
    SignalCategory.MEMORY,
    SignalCategory.INJECTION,
})

# Signal categories indicating trust boundaries for tiebreaker 2
_TRUST_BOUNDARY_CATEGORIES: frozenset[SignalCategory] = frozenset({
    SignalCategory.AUTH,
    SignalCategory.PRIVILEGE,
})


def _has_dangerous_patterns(func: Function) -> bool:
    """Check if function has memory, injection, or exec-related signals."""
    for sig in func.signals:
        if sig.category in _DANGEROUS_CATEGORIES:
            return True
    return False


def _at_trust_boundary(func: Function) -> bool:
    """Check if function is at a trust boundary.

    A function is at a trust boundary if it is an entry point and has
    auth, privilege, or network-related signals.
    """
    if not func.is_entry_point:
        return False
    for sig in func.signals:
        if sig.category in _TRUST_BOUNDARY_CATEGORIES:
            return True
    return False


def _fan_in(func: Function, call_graph: CallGraph) -> int:
    """Count the number of direct callers (fan-in) for a function."""
    return len(call_graph.callers.get(func.identifier, set()))


def prioritize_targets(
    functions: list[Function],
    scores: list[VulnerabilityScore],
    call_graph: CallGraph,
    max_targets: int | None = None,
) -> list[Target]:
    """Rank functions by score with tiebreakers, return Target list.

    Sorting criteria (in order of priority):
    1. Total vulnerability score (highest first)
    2. Tiebreaker 1: has dangerous patterns (memory, injection)
    3. Tiebreaker 2: at trust boundaries (entry points with auth/privilege)
    4. Tiebreaker 3: high fan-in (many callers in call graph)

    Functions with score < 1.0 are filtered out (should_skip).
    """
    # Build score lookup by function_id
    score_map: dict[str, VulnerabilityScore] = {s.function_id: s for s in scores}

    # Build function lookup by identifier
    func_map: dict[str, Function] = {f.identifier: f for f in functions}

    # Create (function, score) pairs, filtering out functions without scores
    pairs: list[tuple[Function, VulnerabilityScore]] = []
    for func in functions:
        score = score_map.get(func.identifier)
        if score is None:
            continue
        pairs.append((func, score))

    # Sort by composite key (all tiebreakers combined)
    pairs.sort(
        key=lambda pair: (
            pair[1].total,                        # Primary: total score
            _has_dangerous_patterns(pair[0]),      # Tiebreaker 1
            _at_trust_boundary(pair[0]),           # Tiebreaker 2
            _fan_in(pair[0], call_graph),          # Tiebreaker 3
        ),
        reverse=True,
    )

    # Build Target objects with priority rank
    targets: list[Target] = []
    for rank, (func, score) in enumerate(pairs, start=1):
        target = Target(
            function=func,
            score=score,
            priority_rank=rank,
        )
        # Filter out low-score targets
        if target.should_skip:
            continue
        targets.append(target)

    # Cap at max_targets if specified
    if max_targets is not None and len(targets) > max_targets:
        targets = targets[:max_targets]

    return targets
