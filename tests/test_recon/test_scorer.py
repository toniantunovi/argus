"""Tests for vulnerability scoring."""
from pathlib import Path

import pytest

from prowl.models.core import (
    Function,
    ProjectType,
    RubricTier,
    SignalCategory,
    VulnerabilityScore,
)
from prowl.recon.scorer import (
    compute_complexity,
    compute_exposure,
    score_function,
    score_functions,
)
from prowl.recon.extractor import extract_functions
from prowl.recon.signals import detect_signals


def _make_func(name, source, language="python", **kwargs):
    return Function(
        name=name,
        file_path=Path("/fake/file.py"),
        start_line=1,
        end_line=source.count("\n") + 1,
        source=source,
        language=language,
        **kwargs,
    )


class TestScoreWithSignals:
    def test_function_with_multiple_signals_high_score(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        score = score_function(get_user, ProjectType.APPLICATION)
        # get_user has SQL injection (data_access), route decorator (auth), etc.
        assert score.signal_score > 0
        assert score.total > 1.0

    def test_signal_score_sums_category_max_weights(self):
        func = _make_func(
            "dangerous",
            'os.system(cmd)\ncursor.execute(f"SELECT * FROM t WHERE id={x}")',
        )
        score = score_function(func, ProjectType.APPLICATION)
        # Should have signals in at least injection and data_access
        assert score.signal_score >= 2.0


class TestScoreEntryPoint:
    def test_entry_point_gets_exposure(self):
        func = _make_func(
            "handler",
            "def handler(): return 'ok'",
            is_entry_point=True,
        )
        exposure = compute_exposure(func, ProjectType.APPLICATION)
        assert exposure == 1.0

    def test_non_entry_point_no_exposure(self):
        func = _make_func(
            "helper",
            "def helper(): return 42",
            is_entry_point=False,
        )
        exposure = compute_exposure(func, ProjectType.APPLICATION)
        assert exposure == 0.0

    def test_public_with_callers_partial_exposure(self):
        func = _make_func(
            "util",
            "def util(): return 1",
            is_entry_point=False,
            callers=["some_caller"],
        )
        exposure = compute_exposure(func, ProjectType.APPLICATION)
        assert exposure == 0.5

    def test_public_library_function_exposure(self):
        func = _make_func(
            "api_func",
            "def api_func(): return 1",
            is_entry_point=False,
            is_public=True,
        )
        exposure = compute_exposure(func, ProjectType.LIBRARY)
        assert exposure == 0.5


class TestScoreComplexity:
    def test_simple_function_low_complexity(self):
        func = _make_func("simple", "def simple():\n    return 1\n")
        complexity = compute_complexity(func)
        assert complexity == 0

    def test_branching_function_higher_complexity(self):
        source = (
            "def branchy(x):\n"
            "    if x > 0:\n"
            "        for i in range(x):\n"
            "            if i % 2 == 0:\n"
            "                pass\n"
            "            else:\n"
            "                pass\n"
            "    elif x < 0:\n"
            "        while x < 0:\n"
            "            x += 1\n"
        )
        func = _make_func("branchy", source)
        complexity = compute_complexity(func)
        assert complexity > 0

    def test_complexity_modifier_clamped(self):
        # A simple function should have complexity_modifier < 1.0
        func = _make_func("simple", "def simple(): return 1\n")
        score = score_function(func, ProjectType.APPLICATION)
        assert score.complexity_modifier <= 1.0


class TestScoreBelowThreshold:
    def test_simple_no_signals_below_threshold(self):
        func = _make_func("noop", "def noop(): pass\n")
        score = score_function(func, ProjectType.LIBRARY)
        assert score.total < 1.0


class TestRubricTierAssignment:
    def test_conservative_tier(self):
        score = VulnerabilityScore(
            function_id="test",
            signal_score=1.0,
            complexity_modifier=0.1,
            exposure_modifier=0.0,
        )
        assert score.rubric_tier == RubricTier.CONSERVATIVE

    def test_standard_tier(self):
        score = VulnerabilityScore(
            function_id="test",
            signal_score=2.0,
            complexity_modifier=0.3,
            exposure_modifier=0.5,
        )
        assert score.rubric_tier == RubricTier.STANDARD

    def test_aggressive_tier(self):
        score = VulnerabilityScore(
            function_id="test",
            signal_score=3.0,
            complexity_modifier=0.5,
            exposure_modifier=1.0,
        )
        assert score.rubric_tier == RubricTier.AGGRESSIVE

    def test_boundary_standard(self):
        score = VulnerabilityScore(
            function_id="test",
            signal_score=2.5,
            complexity_modifier=0.0,
            exposure_modifier=0.0,
        )
        assert score.rubric_tier == RubricTier.STANDARD

    def test_boundary_aggressive(self):
        score = VulnerabilityScore(
            function_id="test",
            signal_score=4.0,
            complexity_modifier=0.0,
            exposure_modifier=0.0,
        )
        assert score.rubric_tier == RubricTier.AGGRESSIVE


class TestScoreFunctions:
    def test_sorted_descending(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        scores = score_functions(funcs, ProjectType.APPLICATION)
        totals = [s.total for s in scores]
        assert totals == sorted(totals, reverse=True)
