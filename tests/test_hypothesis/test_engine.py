"""Tests for hypothesis engine with MockLLMClient."""
from pathlib import Path

import pytest

from prowl.models.core import (
    Function,
    SignalCategory,
    Severity,
    Target,
    VulnerabilityScore,
    RiskSignal,
)
from prowl.models.hypothesis import Hypothesis, HypothesisResponse, ConfidenceGate
from prowl.models.finding import Finding
from prowl.recon.call_graph import build_call_graph
from prowl.recon.extractor import extract_functions
from prowl.recon.signals import detect_signals
from prowl.context_builder.builder import ContextBuilder
from prowl.hypothesis.engine import HypothesisEngine
from prowl.llm.budget import TokenBudget

from tests.conftest import MockLLMClient


def _setup_engine(python_app, llm_responses=None):
    """Build hypothesis engine with mocks from the python_app fixture."""
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

    llm = MockLLMClient(llm_responses)
    budget = TokenBudget(max_tokens=1_000_000)
    engine = HypothesisEngine(llm, builder, budget)
    return engine, [target], llm


class TestHypothesisGeneration:
    @pytest.mark.asyncio
    async def test_returns_hypotheses(self, python_app):
        engine, targets, llm = _setup_engine(python_app)
        promoted, batched, suppressed, stats = await engine.run(targets)
        # Default MockLLMClient returns confidence=0.8 which is above promote threshold (0.7)
        assert len(promoted) > 0
        assert all(isinstance(f, Finding) for f in promoted)
        # LLM was called
        assert len(llm.calls) > 0
        assert llm.calls[0][0] == "hypothesize"

    @pytest.mark.asyncio
    async def test_finding_has_correct_fields(self, python_app):
        engine, targets, _ = _setup_engine(python_app)
        promoted, _, _, _ = await engine.run(targets)
        finding = promoted[0]
        assert finding.title != ""
        assert finding.function_name == "get_user"
        assert finding.file_path != ""
        assert finding.finding_id.startswith("prowl-")

    @pytest.mark.asyncio
    async def test_custom_llm_response(self, python_app):
        custom_response = HypothesisResponse(hypotheses=[
            Hypothesis(
                title="Custom SQL Injection",
                description="Custom test hypothesis",
                severity=Severity.CRITICAL,
                category=SignalCategory.DATA_ACCESS,
                confidence=0.95,
                reasoning="Custom reasoning",
                attack_scenario="Custom attack",
            )
        ])
        engine, targets, _ = _setup_engine(
            python_app, llm_responses={"hypothesize": custom_response}
        )
        promoted, _, _, _ = await engine.run(targets)
        assert len(promoted) == 1
        assert promoted[0].title == "Custom SQL Injection"
        assert promoted[0].severity == Severity.CRITICAL


class TestConfidenceGating:
    def test_promote(self):
        gate = ConfidenceGate(promote_threshold=0.7, batch_threshold=0.4)
        hyp = Hypothesis(
            title="T", description="D", severity=Severity.HIGH,
            category=SignalCategory.AUTH, confidence=0.8,
        )
        assert gate.classify(hyp) == "promote"

    def test_batch(self):
        gate = ConfidenceGate(promote_threshold=0.7, batch_threshold=0.4)
        hyp = Hypothesis(
            title="T", description="D", severity=Severity.HIGH,
            category=SignalCategory.AUTH, confidence=0.5,
        )
        assert gate.classify(hyp) == "batch"

    def test_suppress(self):
        gate = ConfidenceGate(promote_threshold=0.7, batch_threshold=0.4)
        hyp = Hypothesis(
            title="T", description="D", severity=Severity.HIGH,
            category=SignalCategory.AUTH, confidence=0.2,
        )
        assert gate.classify(hyp) == "suppress"

    @pytest.mark.asyncio
    async def test_low_confidence_suppressed(self, python_app):
        low_confidence = HypothesisResponse(hypotheses=[
            Hypothesis(
                title="Unlikely", description="Low confidence",
                severity=Severity.LOW, category=SignalCategory.AUTH,
                confidence=0.1, reasoning="Unlikely",
            )
        ])
        engine, targets, _ = _setup_engine(
            python_app, llm_responses={"hypothesize": low_confidence}
        )
        promoted, batched, suppressed, stats = await engine.run(targets)
        assert len(promoted) == 0
        assert len(suppressed) == 1

    @pytest.mark.asyncio
    async def test_mid_confidence_batched(self, python_app):
        mid_confidence = HypothesisResponse(hypotheses=[
            Hypothesis(
                title="Maybe", description="Mid confidence",
                severity=Severity.MEDIUM, category=SignalCategory.AUTH,
                confidence=0.5, reasoning="Possible",
            )
        ])
        engine, targets, _ = _setup_engine(
            python_app, llm_responses={"hypothesize": mid_confidence}
        )
        promoted, batched, suppressed, stats = await engine.run(targets)
        assert len(promoted) == 0
        assert len(batched) == 1
