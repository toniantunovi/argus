"""Tests for context assembly."""
from pathlib import Path

import pytest

from argus.models.core import (
    Function,
    SignalCategory,
    Severity,
    Target,
    VulnerabilityScore,
    RiskSignal,
)
from argus.models.context import FunctionContext, FindingContext, ExploitContext
from argus.recon.call_graph import CallGraph, build_call_graph
from argus.recon.extractor import extract_functions
from argus.recon.signals import detect_signals
from argus.context_builder.builder import ContextBuilder


def _build_test_context(python_app):
    """Helper to build a context builder from the python_app fixture."""
    funcs = extract_functions(python_app / "app.py")
    for f in funcs:
        f.signals = detect_signals(f)
    graph = build_call_graph(funcs)
    func_map = {f.identifier: f for f in funcs}
    builder = ContextBuilder(func_map, graph, str(python_app))

    get_user = next(f for f in funcs if f.name == "get_user")
    score = VulnerabilityScore(
        function_id=get_user.identifier,
        signal_score=3.0,
        complexity_modifier=0.2,
        exposure_modifier=1.0,
    )
    target = Target(function=get_user, score=score)
    return builder, target, funcs


class TestBuildHypothesisContext:
    def test_all_fields_populated(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_hypothesis_context(target)
        assert isinstance(ctx, FunctionContext)
        assert ctx.target_name == "get_user"
        assert ctx.target_source != ""
        assert ctx.language == "python"
        assert ctx.target_file != ""
        assert ctx.target_lines[0] > 0
        assert ctx.target_lines[1] >= ctx.target_lines[0]

    def test_has_risk_categories(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_hypothesis_context(target)
        assert len(ctx.risk_categories) > 0

    def test_has_detection_rubric(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_hypothesis_context(target)
        # rubric is loaded from YAML, should be a non-empty string
        assert isinstance(ctx.detection_rubric, str)

    def test_callers_or_callees_populated(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_hypothesis_context(target)
        # get_user calls get_db, so callees should include it
        assert len(ctx.callees) > 0 or len(ctx.callers) > 0


class TestBuildFindingContext:
    def test_all_fields_populated(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_finding_context(
            target,
            hypothesis_title="SQL Injection in get_user",
            hypothesis_desc="f-string SQL",
            hypothesis_category=SignalCategory.DATA_ACCESS,
        )
        assert isinstance(ctx, FindingContext)
        assert ctx.target_name == "get_user"
        assert ctx.hypothesis_title == "SQL Injection in get_user"
        assert ctx.hypothesis_category == SignalCategory.DATA_ACCESS
        assert ctx.sink_code != ""
        assert ctx.language == "python"

    def test_has_evaluation_rubric(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_finding_context(
            target,
            hypothesis_title="test",
            hypothesis_desc="test",
            hypothesis_category=SignalCategory.INJECTION,
        )
        assert isinstance(ctx.evaluation_rubric, str)


class TestBuildExploitContext:
    def test_all_fields_populated(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_exploit_context(
            target,
            finding_category=SignalCategory.DATA_ACCESS,
            finding_severity="high",
            iteration_history=["Attempt 1: failed due to syntax error"],
        )
        assert isinstance(ctx, ExploitContext)
        assert ctx.target_name == "get_user"
        assert ctx.finding_severity == "high"
        assert ctx.finding_category == SignalCategory.DATA_ACCESS
        assert len(ctx.iteration_history) == 1
        assert "Attempt 1" in ctx.iteration_history[0]

    def test_empty_iteration_history(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_exploit_context(
            target,
            finding_category=SignalCategory.DATA_ACCESS,
            finding_severity="medium",
        )
        assert ctx.iteration_history == []

    def test_has_exploit_rubric(self, python_app):
        builder, target, _ = _build_test_context(python_app)
        ctx = builder.build_exploit_context(
            target,
            finding_category=SignalCategory.INJECTION,
            finding_severity="high",
        )
        assert isinstance(ctx.exploit_rubric, str)
