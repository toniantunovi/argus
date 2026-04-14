"""Tests for chain analysis grouping."""
from pathlib import Path

import pytest

from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Finding, Classification
from prowl.recon.call_graph import CallGraph
from prowl.triage.chain_analyzer import ChainAnalyzer

from tests.conftest import MockLLMClient


def _make_finding(file_path, function_name, classification=Classification.EXPLOITABLE,
                  category=SignalCategory.INJECTION, finding_id=None):
    fid = finding_id or f"prowl-{category.value}-{Path(file_path).name}-1"
    return Finding(
        finding_id=fid,
        stable_id=f"prowl-{category.value}-{Path(file_path).name}::{function_name}",
        title=f"Vuln in {function_name}",
        description="Test vulnerability",
        severity=Severity.HIGH,
        category=category,
        classification=classification,
        confidence=0.85,
        file_path=file_path,
        function_name=function_name,
        start_line=1,
        end_line=10,
    )


class TestGroupBySameFunction:
    def test_two_findings_same_function(self):
        graph = CallGraph()
        llm = MockLLMClient()
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "handler", finding_id="f1",
                           category=SignalCategory.INJECTION)
        f2 = _make_finding("/app.py", "handler", finding_id="f2",
                           category=SignalCategory.DATA_ACCESS)

        groups = analyzer._group_findings([f1, f2])
        # Should have a group keyed by "func:/app.py::handler"
        func_groups = {k: v for k, v in groups.items() if k.startswith("func:")}
        assert len(func_groups) >= 1
        group_key = f"func:/app.py::handler"
        assert group_key in func_groups
        assert len(func_groups[group_key]) == 2

    def test_single_finding_no_group(self):
        graph = CallGraph()
        llm = MockLLMClient()
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "handler", finding_id="f1")
        groups = analyzer._group_findings([f1])
        # Single finding should not form a group
        func_groups = {k: v for k, v in groups.items() if k.startswith("func:")}
        assert len(func_groups) == 0


class TestGroupByProximity:
    def test_within_three_hops(self):
        graph = CallGraph()
        # Set up a call graph where func_a calls func_b
        graph.add_call("/app.py::func_a", "/app.py::func_b")

        llm = MockLLMClient()
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "func_a", finding_id="f1")
        f2 = _make_finding("/app.py", "func_b", finding_id="f2")

        groups = analyzer._group_findings([f1, f2])
        # Should have a proximity group
        prox_groups = {k: v for k, v in groups.items() if k.startswith("proximity:")}
        assert len(prox_groups) >= 1

    def test_different_files_no_proximity(self):
        graph = CallGraph()
        llm = MockLLMClient()
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "func_a", finding_id="f1")
        f2 = _make_finding("/other.py", "func_b", finding_id="f2")

        groups = analyzer._group_findings([f1, f2])
        prox_groups = {k: v for k, v in groups.items() if k.startswith("proximity:")}
        assert len(prox_groups) == 0

    def test_false_positive_excluded(self):
        graph = CallGraph()
        llm = MockLLMClient()
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "func_a", finding_id="f1",
                           classification=Classification.FALSE_POSITIVE)
        f2 = _make_finding("/app.py", "func_a", finding_id="f2",
                           classification=Classification.EXPLOITABLE)

        groups = analyzer._group_findings([f1, f2])
        # f1 is FP so won't be in exploitable_findings; no group from 1 finding
        func_groups = {k: v for k, v in groups.items() if k.startswith("func:")}
        assert len(func_groups) == 0


class TestChainAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_returns_empty_for_no_chains(self):
        graph = CallGraph()
        llm = MockLLMClient()  # default evaluate_chain returns is_chain=False
        analyzer = ChainAnalyzer(llm, graph)

        f1 = _make_finding("/app.py", "handler", finding_id="f1",
                           category=SignalCategory.INJECTION)
        f2 = _make_finding("/app.py", "handler", finding_id="f2",
                           category=SignalCategory.DATA_ACCESS)

        chains = await analyzer.analyze([f1, f2])
        # MockLLMClient returns is_chain=False, so no chains
        assert chains == []
