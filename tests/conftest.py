"""Shared test fixtures and mocks."""
import pytest
import asyncio
from pathlib import Path
from argus.models.core import Function, Target, VulnerabilityScore, SignalCategory, Severity, RubricTier
from argus.models.hypothesis import Hypothesis, HypothesisResponse
from argus.models.finding import Finding, Classification
from argus.models.context import FunctionContext, FindingContext, ExploitContext
from argus.config import ArgusConfig

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PYTHON_APP = FIXTURES_DIR / "python_app"
C_PROJECT = FIXTURES_DIR / "c_project"
NODE_APP = FIXTURES_DIR / "node_app"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR

@pytest.fixture
def python_app():
    return PYTHON_APP

@pytest.fixture
def c_project():
    return C_PROJECT

@pytest.fixture
def node_app():
    return NODE_APP

@pytest.fixture
def sample_function():
    return Function(
        name="get_user",
        file_path=PYTHON_APP / "app.py",
        start_line=14,
        end_line=21,
        source='def get_user(user_id):\n    conn = get_db()\n    cursor = conn.cursor()\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    user = cursor.fetchone()\n    conn.close()\n    return jsonify({"user": user})',
        language="python",
        parameters=["user_id"],
        is_entry_point=True,
        decorators=["@app.route"],
    )

@pytest.fixture
def sample_target(sample_function):
    score = VulnerabilityScore(
        function_id=sample_function.identifier,
        signal_score=3.5,
        complexity_modifier=0.3,
        exposure_modifier=1.0,
    )
    return Target(function=sample_function, score=score)

@pytest.fixture
def sample_hypothesis():
    return Hypothesis(
        title="SQL Injection in get_user",
        description="f-string SQL query allows injection",
        severity=Severity.HIGH,
        category=SignalCategory.DATA_ACCESS,
        affected_lines=[17],
        confidence=0.9,
        reasoning="The query uses f-string formatting with user input",
        attack_scenario="Attacker sends user_id=1 OR 1=1",
    )

@pytest.fixture
def sample_finding(sample_hypothesis, sample_function):
    return Finding.from_hypothesis(sample_hypothesis, sample_function)

@pytest.fixture
def default_config():
    return ArgusConfig()


class MockLLMClient:
    """Mock LLM client for testing."""

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.calls = []

    async def hypothesize(self, context: FunctionContext) -> HypothesisResponse:
        self.calls.append(("hypothesize", context.target_name))
        if "hypothesize" in self.responses:
            return self.responses["hypothesize"]
        return HypothesisResponse(hypotheses=[
            Hypothesis(
                title=f"Potential vulnerability in {context.target_name}",
                description="Test hypothesis",
                severity=Severity.HIGH,
                category=context.risk_categories[0] if context.risk_categories else SignalCategory.AUTH,
                confidence=0.8,
                reasoning="Test reasoning",
                attack_scenario="Test attack",
            )
        ])

    async def triage(self, context: FindingContext) -> dict:
        self.calls.append(("triage", context.target_name))
        if "triage" in self.responses:
            return self.responses["triage"]
        return {
            "classification": "exploitable",
            "severity": "high",
            "confidence": 0.85,
            "reasoning": "Test triage reasoning",
            "attack_path": "Test attack path",
        }

    async def generate_poc(self, context: ExploitContext) -> dict:
        self.calls.append(("generate_poc", context.target_name))
        if "generate_poc" in self.responses:
            return self.responses["generate_poc"]
        return {
            "code": "print('PoC executed')",
            "language": context.language,
            "description": "Test PoC",
        }

    async def evaluate_chain(self, findings, rubric) -> dict:
        self.calls.append(("evaluate_chain", len(findings)))
        return {"is_chain": False}

    async def generate_patch(self, context, poc_code) -> str:
        self.calls.append(("generate_patch", context.target_name))
        return "# patched code"

    async def batch_triage(self, contexts) -> list:
        self.calls.append(("batch_triage", len(contexts)))
        return [{"classification": "uncertain", "severity": "medium", "confidence": 0.5, "reasoning": "batch"} for _ in contexts]

    def check_session(self) -> None:
        pass  # Mock always has a valid session


class MockSandboxManager:
    """Mock sandbox for testing."""

    def __init__(self, results: dict | None = None):
        self.results = results or {}
        self.calls = []

    async def execute_poc(self, poc_code, language, target_dir, timeout=30, instrumentation=None):
        self.calls.append(("execute_poc", language))
        if "execute_poc" in self.results:
            return self.results["execute_poc"]
        return {
            "stdout": "PoC executed successfully\nARGUS_PROOF",
            "stderr": "",
            "exit_code": 0,
        }
