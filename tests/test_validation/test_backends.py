"""Tests for Claw Code validation backend."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from argus.config import LLMConfig, SandboxConfig, ValidationConfig
from argus.models.core import Severity, SignalCategory
from argus.models.finding import Finding
from argus.models.poc import ValidationStatus
from argus.validation.claw_backend import ClawValidationBackend, ValidationOutcome


@pytest.fixture
def memory_finding():
    return Finding(
        finding_id="argus-memory-test.c-42",
        stable_id="argus-memory-parser.c::parse_header",
        title="Buffer Overflow in parse_header",
        description="Heap buffer overflow via unchecked memcpy",
        severity=Severity.HIGH,
        category=SignalCategory.MEMORY,
        function_name="parse_header",
        file_path="/tmp/test/src/parser.c",
        start_line=42,
        end_line=80,
        confidence=0.85,
    )


@pytest.fixture
def target():
    t = MagicMock()
    t.function = MagicMock()
    t.function.name = "parse_header"
    t.function.file_path = Path("/tmp/test/src/parser.c")
    t.function.start_line = 42
    t.function.end_line = 80
    t.function.language = "c"
    t.function.source = "void parse_header(char *buf, int len) { memcpy(out, buf, len); }"
    t.target_id = "t1"
    return t


@pytest.fixture
def exploit_context():
    ctx = MagicMock()
    ctx.target_source = "void parse_header(char *buf, int len) { memcpy(out, buf, len); }"
    ctx.target_file = "/tmp/test/src/parser.c"
    ctx.target_lines = (42, 80)
    ctx.call_chain = []
    ctx.exploit_rubric = "Check for buffer overflow via unchecked memcpy"
    ctx.source_code = None
    ctx.framework = None
    ctx.iteration_history = []
    ctx.sanitizer_traces = []
    ctx.finding_category = SignalCategory.MEMORY
    ctx.finding_severity = "high"
    ctx.language = "c"
    return ctx


@pytest.fixture
def claw_backend():
    return ClawValidationBackend(
        config=ValidationConfig(),
        sandbox_config=SandboxConfig(),
        llm_config=LLMConfig(),
        target_dir=Path("/tmp/test"),
    )


class TestClawPromptConstruction:
    def test_prompt_contains_function_name(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "parse_header" in prompt

    def test_prompt_contains_category(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "memory" in prompt

    def test_prompt_contains_asan_instructions_for_memory(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "fsanitize=address" in prompt
        assert "ARGUS_POC_CONFIRMED" in prompt

    def test_prompt_contains_target_source(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "memcpy(out, buf, len)" in prompt

    def test_prompt_contains_max_turns(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "30" in prompt


class TestClawApiKeyResolution:
    def test_explicit_override(self, claw_backend):
        claw_backend.config.claw_api_key_env = "CUSTOM_KEY"
        with patch.dict(os.environ, {"CUSTOM_KEY": "test-value"}):
            name, value = claw_backend._resolve_api_key()
            assert name == "CUSTOM_KEY"
            assert value == "test-value"

    def test_auto_detect_anthropic(self, claw_backend):
        claw_backend.llm_config.provider = "anthropic"
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            name, value = claw_backend._resolve_api_key()
            assert name == "ANTHROPIC_API_KEY"
            assert value == "sk-ant-test"

    def test_auto_detect_openai(self, claw_backend):
        claw_backend.llm_config.provider = "openai"
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            name, value = claw_backend._resolve_api_key()
            assert name == "OPENAI_API_KEY"
            assert value == "sk-test"

    def test_missing_key_returns_empty(self, claw_backend):
        with patch.dict(os.environ, {}, clear=True):
            name, value = claw_backend._resolve_api_key()
            assert value == ""


class TestClawTimeout:
    def test_memory_category_uses_memory_timeout(self, claw_backend, memory_finding):
        assert claw_backend._get_timeout(memory_finding) == 1080

    def test_other_category_uses_default_timeout(self, claw_backend, memory_finding):
        memory_finding.category = SignalCategory.INJECTION
        assert claw_backend._get_timeout(memory_finding) == 720


class TestClawResultParsing:
    def test_asan_in_stderr_confirms(self, claw_backend, memory_finding):
        result = {
            "stdout": "",
            "stderr": "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000ef80",
            "exit_code": 1,
            "poc_code": "int main() {}",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED
        assert outcome.sanitizer_output is not None

    def test_confirmation_marker_confirms(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_POC_CONFIRMED",
            "stderr": "",
            "exit_code": 0,
            "poc_code": "int main() {}",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED

    def test_no_evidence_fails(self, claw_backend, memory_finding):
        result = {
            "stdout": "Nothing happened",
            "stderr": "",
            "exit_code": 0,
            "poc_code": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.FAILED

    def test_poc_code_captured(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_POC_CONFIRMED",
            "stderr": "",
            "exit_code": 0,
            "poc_code": '#include <stdio.h>\nint main() { printf("overflow"); }',
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert "stdio" in outcome.poc_code


class TestValidationOutcome:
    def test_outcome_model_fields(self):
        outcome = ValidationOutcome(
            status=ValidationStatus.CONFIRMED,
            poc_code="int main() {}",
            iterations_used=3,
            success_evidence="asan",
        )
        assert outcome.status == ValidationStatus.CONFIRMED
        assert outcome.poc_code == "int main() {}"
        assert outcome.iterations_used == 3

    def test_outcome_defaults(self):
        outcome = ValidationOutcome(status=ValidationStatus.FAILED)
        assert outcome.poc_code == ""
        assert outcome.iterations_used == 0
        assert outcome.sanitizer_output is None


class TestClawDockerfile:
    def test_c_dockerfile_has_gcc_and_multistage(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("c")
        assert "gcc:13" in df
        assert "rust:" in df  # build stage
        assert "cargo build" in df
        assert "COPY --from=claw-builder" in df
        assert "libasan" in df

    def test_builds_static_musl_binary(self, claw_backend):
        """Claw must be built as a static musl binary to avoid GLIBC mismatches."""
        df = claw_backend._get_claw_dockerfile("c")
        assert "musl" in df
        assert "unknown-linux-musl" in df

    def test_cpp_dockerfile_same_as_c(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("cpp")
        assert "gcc:13" in df
        assert "COPY --from=claw-builder" in df

    def test_python_dockerfile_fallback(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("python")
        assert "python:3.12" in df
        assert "COPY --from=claw-builder" in df
        assert "cargo build" in df


class TestDockerPreFlight:
    def test_check_docker_returns_none_on_success(self, claw_backend):
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        claw_backend._docker_client = mock_client
        assert claw_backend.check_docker() is None

    def test_check_docker_returns_error_on_failure(self, claw_backend):
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("Connection refused")
        claw_backend._docker_client = mock_client
        err = claw_backend.check_docker()
        assert err is not None
        assert "Connection refused" in err

    def test_check_docker_returns_error_when_no_docker(self, claw_backend):
        claw_backend._docker_client = None
        with patch.dict("sys.modules", {"docker": MagicMock(**{"from_env.side_effect": Exception("docker not found")})}):
            err = claw_backend.check_docker()
            assert err is not None
            assert "docker not found" in err


class TestEngineUsesClaw:
    def test_engine_creates_claw_backend(self):
        from argus.validation.engine import ValidationEngine
        from tests.conftest import MockLLMClient, MockSandboxManager
        from argus.context_builder.builder import ContextBuilder
        from argus.llm.budget import TokenBudget

        engine = ValidationEngine(
            llm_client=MockLLMClient(),
            sandbox=MockSandboxManager(),
            context_builder=ContextBuilder(MagicMock(), MagicMock()),
            budget=TokenBudget(),
            target_dir=Path("/tmp/test"),
        )
        assert isinstance(engine.claw, ClawValidationBackend)


class TestEngineFailureLogging:
    """Tests that the validation engine surfaces failures rather than swallowing them."""

    @pytest.fixture
    def engine_deps(self):
        from argus.validation.engine import ValidationEngine
        from tests.conftest import MockLLMClient, MockSandboxManager
        from argus.context_builder.builder import ContextBuilder
        from argus.llm.budget import TokenBudget

        return {
            "llm_client": MockLLMClient(),
            "sandbox": MockSandboxManager(),
            "context_builder": ContextBuilder(MagicMock(), MagicMock()),
            "budget": TokenBudget(),
            "target_dir": Path("/tmp/test"),
        }

    @pytest.fixture
    def finding_and_target(self, memory_finding, target):
        targets = {target.target_id: target}
        return memory_finding, targets

    @pytest.mark.asyncio
    async def test_docker_unavailable_aborts_with_stats(self, engine_deps, finding_and_target):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: "Connection refused"

        finding, targets = finding_and_target
        stats = await engine.run([finding], targets)

        assert stats.docker_unavailable is True
        assert stats.attempted == 0
        assert len(stats.errors) == 1
        assert "Docker" in stats.errors[0]

    @pytest.mark.asyncio
    async def test_no_target_match_tracked_in_stats(self, engine_deps, memory_finding):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        # Pass empty targets dict — finding can't match
        stats = await engine.run([memory_finding], {})

        assert stats.no_target == 1
        assert stats.attempted == 0

    @pytest.mark.asyncio
    async def test_failed_outcome_sets_validation_method(self, engine_deps, finding_and_target):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        async def mock_validate(finding, target, context, max_iter):
            return ValidationOutcome(
                status=ValidationStatus.FAILED,
                stderr="Build failed: missing header",
                iterations_used=1,
            )
        engine.claw.validate = mock_validate

        finding, targets = finding_and_target
        stats = await engine.run([finding], targets)

        assert stats.attempted == 1
        assert stats.failed == 1
        assert finding.validation_attempted is True
        assert finding.validation_method == "failed"

    @pytest.mark.asyncio
    async def test_skipped_outcome_sets_validation_method(self, engine_deps, finding_and_target):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        async def mock_validate(finding, target, context, max_iter):
            return ValidationOutcome(
                status=ValidationStatus.SKIPPED,
                success_evidence="no_api_key",
            )
        engine.claw.validate = mock_validate

        finding, targets = finding_and_target
        stats = await engine.run([finding], targets)

        assert stats.attempted == 1
        assert stats.skipped == 1
        assert finding.validation_attempted is True
        assert finding.validation_method == "skipped"

    @pytest.mark.asyncio
    async def test_confirmed_outcome_tracked(self, engine_deps, finding_and_target):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        async def mock_validate(finding, target, context, max_iter):
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED,
                poc_code="int main() {}",
                iterations_used=2,
                success_evidence="asan",
            )
        engine.claw.validate = mock_validate

        finding, targets = finding_and_target
        stats = await engine.run([finding], targets)

        assert stats.attempted == 1
        assert stats.confirmed == 1
        assert finding.poc_validated is True
        assert finding.validation_attempted is True

    @pytest.mark.asyncio
    async def test_all_failed_flag(self, engine_deps, finding_and_target):
        from argus.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        async def mock_validate(finding, target, context, max_iter):
            return ValidationOutcome(
                status=ValidationStatus.FAILED,
                stderr="error",
            )
        engine.claw.validate = mock_validate

        finding, targets = finding_and_target
        stats = await engine.run([finding], targets)

        assert stats.all_failed is True
