"""Tests for Claw Code validation backend."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from prowl.config import LLMConfig, SandboxConfig, ValidationConfig
from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Finding
from prowl.models.poc import ValidationStatus
from prowl.validation.claw_backend import ClawValidationBackend, ValidationOutcome


@pytest.fixture
def memory_finding():
    return Finding(
        finding_id="prowl-memory-test.c-42",
        stable_id="prowl-memory-parser.c::parse_header",
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
    ctx.server_indicators = []
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
        assert "Sanitizer Instrumentation" in prompt
        assert "ARGUS_VALIDATED" in prompt

    def test_prompt_contains_target_source(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "memcpy(out, buf, len)" in prompt

    def test_prompt_contains_max_turns(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "50" in prompt  # claw_max_turns_build default


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
    def test_always_uses_build_timeout(self, claw_backend, memory_finding):
        assert claw_backend._get_timeout(memory_finding) == 1800  # claw_timeout_build

    def test_other_category_also_uses_build_timeout(self, claw_backend, memory_finding):
        memory_finding.category = SignalCategory.INJECTION
        assert claw_backend._get_timeout(memory_finding) == 1800


class TestClawResultParsing:
    def test_asan_in_stderr_confirms(self, claw_backend, memory_finding):
        result = {
            "stdout": "",
            "stderr": "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000ef80",
            "exit_code": 1,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED
        assert outcome.sanitizer_output is not None

    def test_confirmation_marker_confirms(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_VALIDATED",
            "stderr": "",
            "exit_code": 0,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED

    def test_legacy_marker_also_confirms(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_POC_CONFIRMED",
            "stderr": "",
            "exit_code": 0,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED

    def test_no_evidence_fails(self, claw_backend, memory_finding):
        result = {
            "stdout": "Nothing happened",
            "stderr": "",
            "exit_code": 0,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.FAILED

    def test_test_script_captured(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_VALIDATED",
            "stderr": "",
            "exit_code": 0,
            "test_script": '#!/bin/bash\n./build/curl --data "AAAA" http://localhost',
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert "curl" in outcome.test_script
        assert outcome.poc_code == outcome.test_script


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
        from prowl.validation.engine import ValidationEngine
        from tests.conftest import MockLLMClient
        from prowl.context_builder.builder import ContextBuilder
        from prowl.llm.budget import TokenBudget

        engine = ValidationEngine(
            llm_client=MockLLMClient(),
            context_builder=ContextBuilder(MagicMock(), MagicMock()),
            budget=TokenBudget(),
            target_dir=Path("/tmp/test"),
        )
        assert isinstance(engine.claw, ClawValidationBackend)


class TestEngineFailureLogging:
    """Tests that the validation engine surfaces failures rather than swallowing them."""

    @pytest.fixture
    def engine_deps(self):
        from prowl.validation.engine import ValidationEngine
        from tests.conftest import MockLLMClient
        from prowl.context_builder.builder import ContextBuilder
        from prowl.llm.budget import TokenBudget

        return {
            "llm_client": MockLLMClient(),
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
        from prowl.validation.engine import ValidationEngine

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
        from prowl.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        # Pass empty targets dict — finding can't match
        stats = await engine.run([memory_finding], {})

        assert stats.no_target == 1
        assert stats.attempted == 0

    @pytest.mark.asyncio
    async def test_failed_outcome_sets_validation_method(self, engine_deps, finding_and_target):
        from prowl.validation.engine import ValidationEngine

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
        from prowl.validation.engine import ValidationEngine

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
        from prowl.validation.engine import ValidationEngine

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
        from prowl.validation.engine import ValidationEngine

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


class TestBuildProjectPrompt:
    """Tests for the build-project prompt structure."""

    def test_c_prompt_has_build_phases(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "Phase 1: Explore Build System" in prompt
        assert "Phase 2: Build with Sanitizer Instrumentation" in prompt
        assert "Phase 3: Identify Trigger Path" in prompt
        assert "Phase 4: Craft Input and Run" in prompt
        assert "Phase 5: Verify Reachability" in prompt

    def test_c_prompt_forbids_standalone_poc(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "DO NOT write standalone PoC" in prompt
        assert "build and run the ACTUAL project" in prompt

    def test_c_prompt_includes_build_system_commands(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.build_system_hint = "cmake"
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "cmake" in prompt
        assert "CMAKE_C_FLAGS" in prompt

    def test_c_prompt_includes_function_name_in_verify(self, claw_backend, memory_finding, target, exploit_context):
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "`parse_header`" in prompt

    def test_python_prompt_has_install_and_start(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "python"
        memory_finding.category = SignalCategory.INJECTION
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "pip install" in prompt
        assert "Start the actual application" in prompt
        assert "curl" in prompt.lower() or "requests" in prompt.lower()

    def test_node_prompt_has_npm_install(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "node"
        memory_finding.category = SignalCategory.INJECTION
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "npm install" in prompt

    def test_go_prompt_has_go_build(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "go"
        memory_finding.category = SignalCategory.INJECTION
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "go build" in prompt

    def test_rust_prompt_has_cargo_build(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "rust"
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "cargo build" in prompt

    def test_java_prompt_has_maven_or_gradle(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "java"
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "mvn package" in prompt or "gradle build" in prompt


class TestBuildSystemDetection:
    """Tests for build system detection in the context builder."""

    def test_cmake_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "CMakeLists.txt").touch()
        assert detect_build_system(str(tmp_path)) == "cmake"

    def test_autotools_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "configure.ac").touch()
        assert detect_build_system(str(tmp_path)) == "autotools"

    def test_meson_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "meson.build").touch()
        assert detect_build_system(str(tmp_path)) == "meson"

    def test_makefile_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "Makefile").touch()
        assert detect_build_system(str(tmp_path)) == "make"

    def test_npm_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "package.json").touch()
        assert detect_build_system(str(tmp_path)) == "npm"

    def test_pip_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "pyproject.toml").touch()
        assert detect_build_system(str(tmp_path)) == "pip"

    def test_cargo_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "Cargo.toml").touch()
        assert detect_build_system(str(tmp_path)) == "cargo"

    def test_go_detected(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "go.mod").touch()
        assert detect_build_system(str(tmp_path)) == "go"

    def test_cmake_takes_priority_over_makefile(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        (tmp_path / "CMakeLists.txt").touch()
        (tmp_path / "Makefile").touch()
        assert detect_build_system(str(tmp_path)) == "cmake"

    def test_no_build_system(self, tmp_path):
        from prowl.context_builder.builder import detect_build_system
        assert detect_build_system(str(tmp_path)) is None

    def test_nonexistent_dir(self):
        from prowl.context_builder.builder import detect_build_system
        assert detect_build_system("/nonexistent/path") is None


class TestInstrumentationHelpers:
    """Tests for build-system-specific sanitizer injection."""

    def test_cmake_sanitizer_args(self):
        from prowl.sandbox.instrumentation import get_cmake_sanitizer_args
        result = get_cmake_sanitizer_args(["asan", "ubsan"])
        assert "CMAKE_C_FLAGS" in result
        assert "CMAKE_CXX_FLAGS" in result
        assert "fsanitize=address" in result
        assert "fsanitize=undefined" in result

    def test_autotools_sanitizer_env(self):
        from prowl.sandbox.instrumentation import get_autotools_sanitizer_env
        result = get_autotools_sanitizer_env(["asan", "ubsan"])
        assert "CFLAGS=" in result
        assert "LDFLAGS=" in result
        assert "fsanitize=address" in result

    def test_meson_sanitizer_args(self):
        from prowl.sandbox.instrumentation import get_meson_sanitizer_args
        result = get_meson_sanitizer_args(["asan", "ubsan"])
        assert "b_sanitize=" in result
        assert "address" in result
        assert "undefined" in result

    def test_make_sanitizer_override(self):
        from prowl.sandbox.instrumentation import get_make_sanitizer_override
        result = get_make_sanitizer_override(["asan"])
        assert "CFLAGS=" in result
        assert "fsanitize=address" in result

    def test_empty_instrumentation(self):
        from prowl.sandbox.instrumentation import get_meson_sanitizer_args
        assert get_meson_sanitizer_args([]) == ""


class TestEnrichedDockerfile:
    """Tests for the enriched build-project Docker images."""

    def test_c_has_cmake_and_autotools(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("c")
        assert "cmake" in df
        assert "autoconf" in df
        assert "libssl-dev" in df

    def test_c_has_claw_binary(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("c")
        assert "COPY --from=claw-builder" in df
        assert "cargo build" in df

    def test_python_has_gcc_and_git(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("python")
        assert "gcc" in df
        assert "git" in df

    def test_node_has_build_tools(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("node")
        assert "node:20" in df
        assert "git" in df

    def test_go_image(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("go")
        assert "golang:" in df

    def test_rust_image(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("rust")
        assert "rust:" in df

    def test_java_has_maven(self, claw_backend):
        df = claw_backend._get_claw_dockerfile("java")
        assert "maven" in df


class TestTargetFunctionInTrace:
    """Tests for target function detection in ASAN traces."""

    def test_asan_with_target_function_in_trace(self, claw_backend, memory_finding):
        result = {
            "stdout": "",
            "stderr": (
                "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x55 in parse_header /src/parser.c:42\n"
            ),
            "exit_code": 1,
            "test_script": "#!/bin/bash\n./curl http://evil",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED
        assert "parse_header" in outcome.success_evidence

    def test_asan_without_target_function_in_trace(self, claw_backend, memory_finding):
        result = {
            "stdout": "",
            "stderr": (
                "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x55 in other_function /src/other.c:10\n"
            ),
            "exit_code": 1,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED
        assert outcome.success_evidence == "asan"

    def test_validated_marker(self, claw_backend, memory_finding):
        result = {
            "stdout": "ARGUS_VALIDATED",
            "stderr": "",
            "exit_code": 0,
            "test_script": "",
            "build_log": "",
        }
        outcome = claw_backend._parse_result(memory_finding, result)
        assert outcome.status == ValidationStatus.CONFIRMED
        assert outcome.success_evidence == "marker"


class TestServerModePrompt:
    """Tests for server-mode C/C++ and Go prompt generation."""

    def test_c_server_mode_has_start_server_phase(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = ["POSIX listen()", "POSIX accept()"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "network server" in prompt
        assert "POSIX listen()" in prompt
        assert "Start Server" in prompt or "Start the Server" in prompt or "SERVER_PID" in prompt
        assert "Kill the server" in prompt or "kill $SERVER_PID" in prompt

    def test_c_server_mode_has_asan_log_path(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = ["ae event loop (Redis-style)"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "asan.log" in prompt or "ASAN_OPTIONS" in prompt

    def test_c_server_mode_mentions_client_tools(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = ["POSIX listen()"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "nc" in prompt or "netcat" in prompt or "curl" in prompt or "redis-cli" in prompt

    def test_c_server_mode_wait_for_ready(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = ["POSIX listen()"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "wait" in prompt.lower() or "ready" in prompt.lower() or "nc -z" in prompt

    def test_c_cli_mode_when_no_indicators(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = []
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "Identify Trigger Path" in prompt
        assert "Craft Input and Run" in prompt
        # Should still have a fallback note about servers
        assert "server" in prompt.lower()

    def test_c_cli_mode_still_mentions_server_fallback(self, claw_backend, memory_finding, target, exploit_context):
        exploit_context.server_indicators = []
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "network server" in prompt.lower() or "server/daemon" in prompt.lower()

    def test_go_server_mode(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "go"
        memory_finding.category = SignalCategory.AUTH
        exploit_context.server_indicators = ["HTTP server", "Gorilla Mux router"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "network server" in prompt
        assert "HTTP server" in prompt
        assert "SERVER_PID" in prompt

    def test_go_cli_mode(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "go"
        memory_finding.category = SignalCategory.INJECTION
        exploit_context.server_indicators = []
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "Identify Trigger Path" in prompt

    def test_rust_server_mode(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "rust"
        exploit_context.server_indicators = ["actix-web server"]
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "network server" in prompt
        assert "actix-web server" in prompt

    def test_rust_cli_mode(self, claw_backend, memory_finding, target, exploit_context):
        target.function.language = "rust"
        exploit_context.server_indicators = []
        prompt = claw_backend._build_claw_prompt(memory_finding, target, exploit_context)
        assert "Identify Trigger Path" in prompt


class TestServerIndicatorDetection:
    """Tests for server indicator detection in the context builder."""

    def test_c_listen_accept_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "c"
        func.source = "int main() { int fd = socket(AF_INET, SOCK_STREAM, 0); listen(fd, 128); accept(fd, NULL, NULL); }"
        func.identifier = "main"
        indicators = detect_server_indicators("c", {"main": func})
        assert "POSIX listen()" in indicators
        assert "POSIX accept()" in indicators

    def test_c_epoll_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "c"
        func.source = "int epfd = epoll_create(1);"
        func.identifier = "setup_event_loop"
        indicators = detect_server_indicators("c", {"setup_event_loop": func})
        assert "epoll event loop" in indicators

    def test_c_redis_style_ae_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "c"
        func.source = "aeEventLoop *el = aeCreateEventLoop(1024); aeMain(el);"
        func.identifier = "main"
        indicators = detect_server_indicators("c", {"main": func})
        assert "ae event loop (Redis-style)" in indicators
        assert "ae event loop creation" in indicators

    def test_c_libevent_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "c"
        func.source = "struct event_base *base = event_base_new(); event_base_dispatch(base);"
        func.identifier = "main"
        indicators = detect_server_indicators("c", {"main": func})
        assert "libevent event loop" in indicators

    def test_c_no_server_patterns(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "c"
        func.source = "int main(int argc, char *argv[]) { parse_json(argv[1]); return 0; }"
        func.identifier = "main"
        indicators = detect_server_indicators("c", {"main": func})
        assert indicators == []

    def test_go_http_server_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "go"
        func.source = 'func main() { http.ListenAndServe(":8080", mux.NewRouter()) }'
        func.identifier = "main"
        indicators = detect_server_indicators("go", {"main": func})
        assert "HTTP server" in indicators
        assert "Gorilla Mux router" in indicators

    def test_go_grpc_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "go"
        func.source = "s := grpc.NewServer()"
        func.identifier = "main"
        indicators = detect_server_indicators("go", {"main": func})
        assert "gRPC server" in indicators

    def test_go_no_server_patterns(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "go"
        func.source = "func main() { fmt.Println(processFile(os.Args[1])) }"
        func.identifier = "main"
        indicators = detect_server_indicators("go", {"main": func})
        assert indicators == []

    def test_rust_actix_detected(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "rust"
        func.source = "HttpServer::new(|| App::new()).bind('0.0.0.0:8080')?.run().await"
        func.identifier = "main"
        indicators = detect_server_indicators("rust", {"main": func})
        assert "actix-web server" in indicators

    def test_unsupported_language_returns_empty(self):
        from prowl.context_builder.builder import detect_server_indicators
        func = MagicMock()
        func.language = "python"
        func.source = "app.run()"
        func.identifier = "main"
        indicators = detect_server_indicators("python", {"main": func})
        assert indicators == []

    def test_cross_language_functions_ignored(self):
        from prowl.context_builder.builder import detect_server_indicators
        c_func = MagicMock()
        c_func.language = "c"
        c_func.source = "int main() { return 0; }"
        c_func.identifier = "main"
        go_func = MagicMock()
        go_func.language = "go"
        go_func.source = 'http.ListenAndServe(":8080", nil)'
        go_func.identifier = "go_main"
        # Asking for C indicators should not pick up Go patterns
        indicators = detect_server_indicators("c", {"main": c_func, "go_main": go_func})
        assert indicators == []

    def test_deduplication(self):
        from prowl.context_builder.builder import detect_server_indicators
        func1 = MagicMock()
        func1.language = "c"
        func1.source = "listen(fd, 128);"
        func1.identifier = "setup1"
        func2 = MagicMock()
        func2.language = "c"
        func2.source = "listen(fd2, 64);"
        func2.identifier = "setup2"
        indicators = detect_server_indicators("c", {"setup1": func1, "setup2": func2})
        assert indicators.count("POSIX listen()") == 1


class TestEngineRecordsStrategy:
    """Tests that the validation engine records the strategy on findings."""

    @pytest.fixture
    def engine_deps(self):
        from prowl.validation.engine import ValidationEngine
        from tests.conftest import MockLLMClient
        from prowl.context_builder.builder import ContextBuilder
        from prowl.llm.budget import TokenBudget

        return {
            "llm_client": MockLLMClient(),
            "context_builder": ContextBuilder(MagicMock(), MagicMock()),
            "budget": TokenBudget(),
            "target_dir": Path("/tmp/test"),
        }

    @pytest.mark.asyncio
    async def test_strategy_recorded_on_finding(self, engine_deps, memory_finding, target):
        from prowl.validation.engine import ValidationEngine

        engine = ValidationEngine(**engine_deps)
        engine.claw.check_docker = lambda: None

        async def mock_validate(finding, target, context, max_iter):
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED,
                test_script="#!/bin/bash\n./binary --crash",
                iterations_used=3,
                success_evidence="asan",
            )
        engine.claw.validate = mock_validate

        targets = {target.target_id: target}
        stats = await engine.run([memory_finding], targets)

        assert stats.confirmed == 1
        assert memory_finding.validation_strategy == "build_project"
        assert "binary" in memory_finding.poc_code
