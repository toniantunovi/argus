"""Vulnerability likelihood scoring.

Computes a composite score for each function:

    score = signal_score + complexity_modifier + exposure_modifier

- signal_score:       sum of max weight per category across matched signals
- complexity_modifier: cyclomatic complexity normalised to 0-1.0 (complexity/20, clamped)
- exposure_modifier:  +1.0 if entry point or exported, +0.5 if called from an entry point
"""
from __future__ import annotations

from argus.models.core import (
    Function,
    ProjectType,
    SignalCategory,
    VulnerabilityScore,
)
from argus.recon.parser import parse_source
from argus.recon.signals import detect_signals

# ---------------------------------------------------------------------------
# Branch node types per language for cyclomatic complexity
# ---------------------------------------------------------------------------

_BRANCH_NODES: dict[str, set[str]] = {
    "python": {
        "if_statement",
        "elif_clause",
        "else_clause",
        "for_statement",
        "while_statement",
        "try_statement",
        "except_clause",
        "with_statement",
        "boolean_operator",         # and / or
        "conditional_expression",   # ternary
        "assert_statement",
        "raise_statement",
        "list_comprehension",
        "generator_expression",
    },
    "javascript": {
        "if_statement",
        "else_clause",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "ternary_expression",
        "binary_expression",        # for && and ||, filtered below
        "optional_chain_expression",
    },
    "typescript": {
        "if_statement",
        "else_clause",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "ternary_expression",
        "binary_expression",
        "optional_chain_expression",
    },
    "tsx": {
        "if_statement",
        "else_clause",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "ternary_expression",
        "binary_expression",
        "optional_chain_expression",
    },
    "java": {
        "if_statement",
        "else_clause",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "switch_expression",
        "switch_block_statement_group",
        "catch_clause",
        "ternary_expression",
        "binary_expression",
    },
    "go": {
        "if_statement",
        "else_clause",
        "for_statement",
        "expression_switch_statement",
        "type_switch_statement",
        "select_statement",
        "communication_case",
        "default_case",
        "binary_expression",
    },
    "rust": {
        "if_expression",
        "else_clause",
        "for_expression",
        "while_expression",
        "loop_expression",
        "match_arm",
        "binary_expression",
    },
    "c": {
        "if_statement",
        "else_clause",
        "for_statement",
        "while_statement",
        "do_statement",
        "case_statement",
        "conditional_expression",
        "binary_expression",
    },
    "cpp": {
        "if_statement",
        "else_clause",
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
        "case_statement",
        "catch_clause",
        "conditional_expression",
        "binary_expression",
        "try_statement",
    },
    "ruby": {
        "if",
        "elsif",
        "else",
        "unless",
        "case",
        "when",
        "while",
        "until",
        "for",
        "rescue",
        "binary",
    },
    "php": {
        "if_statement",
        "else_clause",
        "elseif_clause",
        "for_statement",
        "foreach_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "conditional_expression",
        "binary_expression",
    },
}

# Binary operators that count as branches (short-circuit evaluation)
_LOGICAL_OPERATORS: set[str] = {"&&", "||", "and", "or"}


# ---------------------------------------------------------------------------
# Complexity
# ---------------------------------------------------------------------------

def _count_branch_nodes(node, branch_types: set[str]) -> int:  # noqa: ANN001
    """Recursively count branch nodes in a tree-sitter AST."""
    count = 0
    if node.type in branch_types:
        # For binary_expression / boolean_operator, only count if operator is logical
        if node.type in ("binary_expression", "boolean_operator", "binary"):
            op_node = node.child_by_field_name("operator")
            if op_node is not None:
                op_text = op_node.text.decode("utf-8", errors="replace") if hasattr(op_node.text, 'decode') else str(op_node.text)
                if op_text in _LOGICAL_OPERATORS:
                    count += 1
            # Fallback: check children for operator text
            elif any(
                child.type in ("&&", "||", "and", "or")
                for child in node.children
                if not child.is_named
            ):
                count += 1
        else:
            count += 1

    for child in node.children:
        count += _count_branch_nodes(child, branch_types)

    return count


def compute_complexity(function: Function) -> int:
    """Compute cyclomatic complexity by counting branch nodes in the AST.

    Returns the raw count of branch nodes (not normalised).
    If tree-sitter parsing fails, falls back to a simple regex heuristic.
    """
    language = function.language
    branch_types = _BRANCH_NODES.get(language)
    if branch_types is None:
        # Unknown language -- fall back to a keyword heuristic
        return _heuristic_complexity(function.source)

    source_bytes = function.source.encode("utf-8")
    tree = parse_source(source_bytes, language)
    if tree is None:
        return _heuristic_complexity(function.source)

    return _count_branch_nodes(tree.root_node, branch_types)


def _heuristic_complexity(source: str) -> int:
    """Rough keyword-based complexity estimate when AST is unavailable."""
    import re
    keywords = re.findall(
        r"\b(if|elif|else|for|while|case|switch|catch|except|and|or|&&|\|\|)\b",
        source,
    )
    return len(keywords)


# ---------------------------------------------------------------------------
# Exposure
# ---------------------------------------------------------------------------

def compute_exposure(function: Function, project_type: ProjectType) -> float:
    """Compute exposure modifier.

    +1.0 if the function is an entry point or a public export.
    +0.5 if the function is called directly by an entry point.
    0.0 otherwise.
    """
    # Entry points get full exposure bonus
    if function.is_entry_point:
        return 1.0

    # Public + application context => likely reachable
    if function.is_public and project_type in (ProjectType.APPLICATION, ProjectType.MIXED):
        # Check decorators for route/endpoint indicators
        route_indicators = {
            "route", "get", "post", "put", "delete", "patch",
            "api_view", "action", "endpoint", "RequestMapping",
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
            "Controller", "RestController",
        }
        for dec in function.decorators:
            dec_lower = dec.lower()
            if any(ind.lower() in dec_lower for ind in route_indicators):
                return 1.0

    # Called from an entry point
    if function.callers:
        # If any caller identifier looks like an entry point, return 0.5.
        # We use a simple heuristic: the callers list is populated by the
        # pipeline with identifiers; the presence of callers alone suggests
        # reachability. In a full pipeline, we'd cross-reference with the
        # entry point set.
        return 0.5

    # Public functions in libraries get a small boost
    if function.is_public and project_type == ProjectType.LIBRARY:
        return 0.5

    return 0.0


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_function(
    function: Function, project_type: ProjectType
) -> VulnerabilityScore:
    """Compute the full vulnerability score for a single function.

    Side-effects: populates ``function.signals`` and ``function.complexity``.
    """
    # 1. Detect signals
    signals = detect_signals(function)
    function.signals = signals
    function.complexity = compute_complexity(function)

    # 2. Signal score: max weight per category (dedup)
    category_max: dict[SignalCategory, float] = {}
    for sig in signals:
        current = category_max.get(sig.category, 0.0)
        if sig.weight > current:
            category_max[sig.category] = sig.weight
    signal_score = sum(category_max.values())

    # 3. Complexity modifier: normalise to 0-1.0
    complexity_modifier = min(function.complexity / 20.0, 1.0)

    # 4. Exposure modifier
    exposure_modifier = compute_exposure(function, project_type)

    return VulnerabilityScore(
        function_id=function.identifier,
        signal_score=signal_score,
        complexity_modifier=complexity_modifier,
        exposure_modifier=exposure_modifier,
    )


def score_functions(
    functions: list[Function], project_type: ProjectType
) -> list[VulnerabilityScore]:
    """Score a batch of functions and return their vulnerability scores.

    Results are sorted by total score descending (highest risk first).
    """
    scores = [score_function(f, project_type) for f in functions]
    scores.sort(key=lambda s: s.total, reverse=True)
    return scores
