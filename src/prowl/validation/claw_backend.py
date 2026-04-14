"""Claw Code agentic validation backend.

Validates findings by building the actual target project and running the real
binaries with crafted inputs — no standalone PoC code.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import threading
from pathlib import Path

from pydantic import BaseModel

from prowl.config import LLMConfig, SandboxConfig, ValidationConfig
from prowl.models.context import ExploitContext
from prowl.models.core import SignalCategory, Target
from prowl.models.finding import Finding
from prowl.models.poc import ValidationStatus
from prowl.sandbox.instrumentation import (
    get_autotools_sanitizer_env,
    get_cmake_sanitizer_args,
    get_make_sanitizer_override,
    get_meson_sanitizer_args,
    parse_sanitizer_output,
)
from prowl.validation.result_checker import check_result


class ValidationOutcome(BaseModel):
    """Result of a Claw validation attempt."""
    status: ValidationStatus
    poc_code: str = ""
    test_script: str = ""
    build_log: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    sanitizer_output: dict | None = None
    iterations_used: int = 0
    success_evidence: str = ""

logger = logging.getLogger(__name__)

# Default env var names per LLM provider (mirrors langchain_client.py)
_DEFAULT_API_KEY_ENVS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
}


class ClawValidationBackend:
    """Agentic validation via Claw Code running inside the Docker sandbox."""

    def __init__(
        self,
        config: ValidationConfig,
        sandbox_config: SandboxConfig,
        llm_config: LLMConfig,
        target_dir: Path,
    ):
        self.config = config
        self.sandbox_config = sandbox_config
        self.llm_config = llm_config
        self.target_dir = target_dir
        self._docker_client = None
        self._image_cache: dict[str, bool] = {}
        self._image_build_lock = threading.Lock()

    def _get_docker_client(self):
        if self._docker_client is None:
            import docker
            self._docker_client = docker.from_env()
        return self._docker_client

    def check_docker(self) -> str | None:
        """Pre-flight check for Docker connectivity.

        Returns None if Docker is available, or an error message string.
        """
        try:
            client = self._get_docker_client()
            client.ping()
            return None
        except Exception as e:
            return str(e)

    def _resolve_api_key(self) -> tuple[str, str]:
        """Resolve the API key env var name and value to forward into the container.

        Returns (env_var_name, env_var_value).
        """
        # Explicit override
        if self.config.claw_api_key_env:
            val = os.environ.get(self.config.claw_api_key_env, "")
            return self.config.claw_api_key_env, val

        # Auto-detect from LLM config
        env_var = self.llm_config.api_key_env or _DEFAULT_API_KEY_ENVS.get(
            self.llm_config.provider, ""
        )
        if env_var:
            return env_var, os.environ.get(env_var, "")
        return "ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY", "")

    def _resolve_model(self) -> str:
        """Resolve the model name Claw should use — validation layer override
        falls back to the global llm.model.
        """
        layer_model = self.llm_config.validation.model
        return layer_model or self.llm_config.model

    def _get_timeout(self, finding: Finding) -> int:
        """Get wall-clock timeout — uses the build timeout since we compile the real project."""
        return self.config.claw_timeout_build

    async def validate(
        self,
        finding: Finding,
        target: Target,
        context: ExploitContext,
        max_iterations: int,
    ) -> ValidationOutcome:
        """Run Claw Code agent inside Docker to develop and execute a PoC."""
        timeout = self._get_timeout(finding)
        prompt = self._build_claw_prompt(finding, target, context)
        api_key_name, api_key_value = self._resolve_api_key()
        model = self._resolve_model()

        if not api_key_value:
            logger.error(
                "No API key found for Claw backend (%s). Skipping %s",
                api_key_name, finding.finding_id,
            )
            return ValidationOutcome(
                status=ValidationStatus.SKIPPED,
                iterations_used=0,
                success_evidence="no_api_key",
            )

        try:
            image_tag = await self._ensure_image(target.function.language)
            result = await asyncio.to_thread(
                self._run_claw_container,
                image_tag, prompt, api_key_name, api_key_value, model, timeout,
            )
            return self._parse_result(finding, result)
        except Exception as e:
            logger.error("Claw validation failed for %s: %s", finding.finding_id, e)
            return ValidationOutcome(
                status=ValidationStatus.FAILED,
                stderr=str(e),
                iterations_used=0,
            )

    def _build_claw_prompt(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> str:
        """Build the task prompt for Claw Code.

        The prompt instructs Claw to build and run the actual target project
        (not write standalone PoC code).  The approach varies by language.
        """
        lang = target.function.language
        parts = self._build_common_header(finding, target, context)

        if lang in ("c", "cpp"):
            parts.extend(self._build_c_cpp_phases(finding, target, context))
        elif lang in ("python",):
            parts.extend(self._build_python_phases(finding, target, context))
        elif lang in ("node", "javascript", "typescript"):
            parts.extend(self._build_node_phases(finding, target, context))
        elif lang == "go":
            parts.extend(self._build_go_phases(finding, target, context))
        elif lang == "rust":
            parts.extend(self._build_rust_phases(finding, target, context))
        elif lang == "java":
            parts.extend(self._build_java_phases(finding, target, context))
        else:
            parts.extend(self._build_generic_phases(finding, target, context))

        parts.extend(self._build_common_footer(context))
        return "\n".join(parts)

    def _build_common_header(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Vulnerability info and context shared by all language prompts."""
        parts = [
            "You are inside a Docker container with the target codebase at /app/target.",
            "Your task: build and run the ACTUAL project, then exercise the real binary/server "
            "with crafted inputs to trigger the following vulnerability.",
            "DO NOT write standalone PoC code. You must build and use the real project.\n",
            f"## Vulnerability: {finding.title}",
            f"Category: {finding.category.value}",
            f"Severity: {finding.severity.value}",
            f"Function: {target.function.name} in {target.function.file_path}:"
            f"{target.function.start_line}-{target.function.end_line}\n",
            f"## Description\n{finding.description}\n",
            "## Vulnerable Code",
            f"```\n{context.target_source}\n```\n",
        ]

        if context.call_chain:
            parts.append("## Call Chain (entry point to sink)")
            for i, step in enumerate(context.call_chain[:5]):
                parts.append(f"Step {i + 1}:\n```\n{step}\n```")
            parts.append("")

        if finding.attack_scenario:
            parts.append(f"## Attack Scenario\n{finding.attack_scenario}\n")

        if context.exploit_rubric:
            parts.append(f"## Exploit Guidance\n{context.exploit_rubric}\n")

        return parts

    def _build_c_cpp_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for C/C++ projects: build with ASAN, run the real binary."""
        instrumentation = self.config.instrumentation
        build_hint = context.build_system_hint

        # Prepare build-system-specific commands
        build_commands: list[str] = []
        if build_hint == "cmake":
            args = get_cmake_sanitizer_args(instrumentation)
            build_commands = [
                f"  mkdir -p build && cd build && cmake .. {args} && make -j$(nproc)",
            ]
        elif build_hint == "autotools":
            env = get_autotools_sanitizer_env(instrumentation)
            build_commands = [
                f"  {env} ./configure && make -j$(nproc)",
                "  (If configure does not exist, run autoreconf -fi first)",
            ]
        elif build_hint == "meson":
            args = get_meson_sanitizer_args(instrumentation)
            build_commands = [
                f"  meson setup builddir {args} && ninja -C builddir",
            ]
        elif build_hint == "make":
            override = get_make_sanitizer_override(instrumentation)
            build_commands = [
                f"  make {override} -j$(nproc)",
            ]
        else:
            cmake_args = get_cmake_sanitizer_args(instrumentation)
            autotools_env = get_autotools_sanitizer_env(instrumentation)
            make_override = get_make_sanitizer_override(instrumentation)
            build_commands = [
                "  Detect the build system and use the appropriate command:",
                f"  - CMake: mkdir build && cd build && cmake .. {cmake_args} && make -j$(nproc)",
                f"  - Autotools: {autotools_env} ./configure && make -j$(nproc)",
                f"  - Plain Make: make {make_override} -j$(nproc)",
            ]

        func_name = target.function.name
        is_server = bool(context.server_indicators)

        parts = [
            "## Phase 1: Explore Build System",
            "- Examine /app/target for CMakeLists.txt, configure, configure.ac, Makefile, meson.build",
            "- Check README, INSTALL, BUILD docs for build instructions",
            "- Check CI configs (.github/workflows/, .circleci/) for build commands",
            "",
            "## Phase 2: Build with Sanitizer Instrumentation",
            "- Copy the source tree: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Build the project with ASAN/UBSAN instrumentation:",
            *build_commands,
            "- If dependencies are missing, install them with apt-get and retry",
            "- DO NOT write standalone PoC code. Build the actual project.",
            "",
        ]

        if is_server:
            parts.extend(self._c_cpp_server_phases(func_name, context))
        else:
            parts.extend(self._c_cpp_cli_phases(func_name))

        return parts

    def _c_cpp_server_phases(
        self, func_name: str, context: ExploitContext,
    ) -> list[str]:
        """Phases 3-5 for C/C++ server/daemon projects (Redis, nginx, memcached, etc.)."""
        indicators = ", ".join(context.server_indicators)
        return [
            "## Phase 3: Identify Server Binary and Client",
            f"- This project is a **network server** (detected: {indicators})",
            f"- The vulnerable function is `{func_name}`",
            "- Identify:",
            "  - Which compiled binary is the server (check Makefile targets, README, src/ layout)",
            "  - What port it listens on (check config files, default port, command-line flags)",
            "  - What protocol it speaks (HTTP, custom TCP, Redis protocol, etc.)",
            "  - What client tool to use (curl, nc/netcat, the project's own CLI client, redis-cli, etc.)",
            "  - What command or request reaches the vulnerable function through the call chain",
            "",
            "## Phase 4: Start Server, Connect, and Send Crafted Input",
            "- Write a test script (test.sh) in /app/work that does the following steps:",
            "  1. Set ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=/app/work/asan.log",
            "  2. Start the instrumented server in background:",
            "     ./server-binary [flags] &",
            "     SERVER_PID=$!",
            "  3. Wait for it to be ready:",
            "     - Try: until nc -z localhost <port> 2>/dev/null; do sleep 0.5; done",
            "     - Or check stdout/log for 'ready', 'listening', 'started'",
            "     - Timeout after 30 seconds if it never starts",
            "  4. Send crafted commands/requests via the client:",
            "     - Use the project's own CLI client if available (e.g. redis-cli, mysql, psql)",
            "     - Or use nc/netcat for raw TCP protocols",
            "     - Or use curl for HTTP servers",
            "     - Send input designed to reach the vulnerable function through the call chain",
            "  5. Capture the server's stderr and the ASAN log file for sanitizer output",
            "  6. Kill the server: kill $SERVER_PID; wait $SERVER_PID 2>/dev/null",
            '  7. If ASAN/UBSAN fired (check asan.log and stderr), print "ARGUS_VALIDATED"',
            "- Run the test script and observe the output",
            "",
            "## Phase 5: Verify Reachability",
            f"- If ASAN fires, verify the stack trace includes `{func_name}`",
            "- If ASAN does not fire, the vulnerable code was not reached — adjust your commands and retry",
            "- Common issues:",
            "  - Wrong port or protocol — check server startup output",
            "  - Server requires authentication — check for default credentials or --no-auth flags",
            "  - Server requires a config file — create a minimal one or use --default flags",
            "  - Vulnerable path requires specific server state — send setup commands first",
            "- You must confirm that the ACTUAL vulnerable function was exercised, not a different bug",
            "- Note: if the server crashes from ASAN, it may not respond to the client — this is expected",
            "",
        ]

    def _c_cpp_cli_phases(self, func_name: str) -> list[str]:
        """Phases 3-5 for C/C++ CLI/library projects (jq, curl, etc.)."""
        return [
            "## Phase 3: Identify Trigger Path",
            f"- The vulnerable function is `{func_name}`",
            "- Based on the call chain above, identify:",
            "  - Which compiled binary/executable exercises this function",
            "  - What input reaches it (CLI args, file input, stdin, network data)",
            "- Trace from the entry point through the call chain to the vulnerable function",
            "- Note: if this project is a network server/daemon, start it in background,",
            "  wait for it to listen, connect with the appropriate client, and send crafted commands.",
            "",
            "## Phase 4: Craft Input and Run",
            "- Write a test script (test.sh) in /app/work that:",
            "  1. Runs the instrumented binary with crafted input that reaches the vulnerable function",
            "  2. Captures stderr for ASAN/UBSAN output",
            '  3. If ASAN/UBSAN fires, prints "ARGUS_VALIDATED" to stdout',
            "- Run the test script and observe the output",
            "",
            "## Phase 5: Verify Reachability",
            f'- If ASAN fires, verify the stack trace includes `{func_name}`',
            "- If ASAN does not fire, the vulnerable code was not reached — adjust your input and retry",
            "- You must confirm that the ACTUAL vulnerable function was exercised, not a different bug",
            "",
        ]

    def _build_python_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for Python projects: install, start the app, send requests."""
        func_name = target.function.name
        framework = context.framework or "unknown"
        return [
            "## Phase 1: Explore Project Structure",
            "- Examine /app/target for the application entry point",
            f"- Framework detected: {framework}",
            "- Check for pyproject.toml, setup.py, setup.cfg, requirements.txt",
            "- Identify the main application module and how the server is started",
            "",
            "## Phase 2: Install and Start the Application",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Install: pip install -e . OR pip install -r requirements.txt",
            "- Start the actual application server in background:",
            "  - Flask: python -m flask run --host=0.0.0.0 --port=8080 &",
            "  - Django: python manage.py runserver 0.0.0.0:8080 &",
            "  - FastAPI: uvicorn app:app --host=0.0.0.0 --port=8080 &",
            "  - Or use the project's own start command",
            "- Wait for it to be ready: until curl -s http://localhost:8080/ > /dev/null 2>&1; do sleep 1; done",
            "- If it is a library/CLI (not a web server), identify the command-line entry point instead",
            "",
            "## Phase 3: Identify Vulnerable Endpoint",
            f"- The vulnerable function is `{func_name}`",
            "- From the call chain, identify the HTTP route/handler or CLI command that calls it",
            "- Determine the request method, URL path, parameters, headers, and body needed",
            "",
            "## Phase 4: Craft and Send Request",
            "- Write a test script (test.sh or test.py) in /app/work that:",
            "  1. Sends crafted HTTP request(s) to the running server (use curl or python requests)",
            "  2. OR runs the CLI with crafted arguments if not a web app",
            "  3. Checks the response for evidence of exploitation",
            '  4. Prints "ARGUS_VALIDATED" to stdout if the vulnerability is confirmed',
            "",
            "## Phase 5: Verify",
            "- For SQLi: verify injected query returns unauthorized data or error reveals DB structure",
            "- For XSS: verify payload is reflected unescaped in response",
            "- For command injection: verify injected command output appears in response",
            "- For auth bypass: verify protected resource is accessible without valid credentials",
            "- For IDOR: verify another user's data is accessible by manipulating IDs",
            f"- Confirm the response demonstrates that `{func_name}` was reached and exploited",
            "",
        ]

    def _build_node_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for Node.js projects: npm install, start, send requests."""
        func_name = target.function.name
        framework = context.framework or "unknown"
        return [
            "## Phase 1: Explore Project Structure",
            "- Examine /app/target for package.json, entry point (main/bin fields)",
            f"- Framework detected: {framework}",
            "- Identify how the server or CLI is started",
            "",
            "## Phase 2: Install and Start the Application",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Install: npm install",
            "- Start the actual application:",
            "  - Express/Koa/Fastify: node server.js & OR npm start &",
            "  - Check package.json scripts for the start command",
            "- Wait for it: until curl -s http://localhost:3000/ > /dev/null 2>&1; do sleep 1; done",
            "- If it is a CLI tool, identify the binary entry point instead",
            "",
            "## Phase 3: Identify Vulnerable Endpoint",
            f"- The vulnerable function is `{func_name}`",
            "- From the call chain, identify the HTTP route/handler or CLI command that calls it",
            "- Determine the request method, URL path, parameters, headers, and body needed",
            "",
            "## Phase 4: Craft and Send Request",
            "- Write a test script (test.sh) in /app/work that:",
            "  1. Sends crafted HTTP request(s) to the running server (use curl)",
            "  2. OR runs the CLI with crafted arguments",
            "  3. Checks the response for evidence of exploitation",
            '  4. Prints "ARGUS_VALIDATED" if the vulnerability is confirmed',
            "",
            "## Phase 5: Verify",
            "- For SQLi: verify injected query returns unauthorized data",
            "- For XSS: verify payload is reflected unescaped in response",
            "- For command injection: verify injected command output appears",
            "- For auth bypass: verify protected resource is accessible without credentials",
            f"- Confirm the response demonstrates that `{func_name}` was reached and exploited",
            "",
        ]

    def _build_go_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for Go projects: go build with race detector, run binary."""
        func_name = target.function.name
        race_flag = "-race" if finding.category == SignalCategory.CONCURRENCY else ""
        is_server = bool(context.server_indicators)

        parts = [
            "## Phase 1: Explore and Build",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Check go.mod for module path and dependencies",
            f"- Build: go build {race_flag} -o /app/work/binary ./...",
            "  (adjust the build target based on the project's cmd/ directory structure)",
            "",
        ]

        if is_server:
            indicators = ", ".join(context.server_indicators)
            parts.extend([
                "## Phase 2: Start the Server",
                f"- This project is a **network server** (detected: {indicators})",
                f"- The vulnerable function is `{func_name}`",
                "- Identify the port it listens on (check flags, config, README)",
                "- Start the server in background:",
                "  /app/work/binary [flags] &",
                "  SERVER_PID=$!",
                "- Wait for it to be ready:",
                "  until nc -z localhost <port> 2>/dev/null; do sleep 0.5; done",
                "  (timeout after 30 seconds)",
                "",
                "## Phase 3: Connect and Send Crafted Requests",
                "- From the call chain, identify what request/command reaches the vulnerable function",
                "- Send crafted requests using curl, the project's CLI client, or nc:",
                "  - HTTP: curl -X POST http://localhost:<port>/path -d '{payload}'",
                "  - gRPC: use grpcurl or the project's own client",
                "  - TCP: echo 'payload' | nc localhost <port>",
                "- Write a test script (test.sh) in /app/work that:",
                "  1. Starts the server in background",
                "  2. Waits for readiness",
                "  3. Sends crafted requests",
                "  4. Checks server output and response for evidence of exploitation",
                "  5. Kills the server",
                '  6. Prints "ARGUS_VALIDATED" if the vulnerability is confirmed',
                "",
                "## Phase 4: Verify",
                f"- Confirm that `{func_name}` was actually executed",
                "- Check for panics, incorrect output, unauthorized data in response, or security violations",
                "- If using -race, check for race condition detector output in server stderr",
                "- If the server requires auth, check for default credentials or --insecure flags",
                "",
            ])
        else:
            parts.extend([
                "## Phase 2: Identify Trigger Path",
                f"- The vulnerable function is `{func_name}`",
                "- Trace the call chain to identify what input reaches this function",
                "- Determine: CLI args, HTTP request, file input, or environment variable",
                "- Note: if this project is a network server, start it in background,",
                "  wait for it to listen, and send crafted requests via curl/nc/client tool.",
                "",
                "## Phase 3: Run with Crafted Input",
                "- If it is a CLI, run with crafted arguments",
                "- Write a test script (test.sh) that runs the binary and checks output",
                '- Print "ARGUS_VALIDATED" if the vulnerability is confirmed',
                "",
                "## Phase 4: Verify",
                f"- Confirm that `{func_name}` was actually executed",
                "- If using -race, check for race condition detector output",
                "- Check for any panics, incorrect output, or security violations",
                "",
            ])

        return parts

    def _build_rust_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for Rust projects: cargo build, run binary."""
        func_name = target.function.name
        is_server = bool(context.server_indicators)

        parts = [
            "## Phase 1: Explore and Build",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Check Cargo.toml for the crate structure",
            "- Build: cargo build",
            "- For unsafe code bugs, build with: RUSTFLAGS='-Zsanitizer=address' cargo +nightly build",
            "",
        ]

        if is_server:
            indicators = ", ".join(context.server_indicators)
            parts.extend([
                "## Phase 2: Start the Server",
                f"- This project is a **network server** (detected: {indicators})",
                f"- The vulnerable function is `{func_name}`",
                "- Identify the port (check config, CLI flags, README)",
                "- Start: ./target/debug/binary [flags] &",
                "  SERVER_PID=$!",
                "- Wait: until nc -z localhost <port> 2>/dev/null; do sleep 0.5; done",
                "",
                "## Phase 3: Send Crafted Requests",
                "- Send crafted HTTP requests or TCP data to trigger the vulnerability",
                "- Write a test script (test.sh) that starts, exercises, and kills the server",
                '- Print "ARGUS_VALIDATED" if confirmed',
                "",
                "## Phase 4: Verify",
                f"- Confirm that `{func_name}` was actually exercised",
                "- Check for panics, sanitizer output, or incorrect behavior",
                "- If the server requires auth, check for default credentials or dev-mode flags",
                "",
            ])
        else:
            parts.extend([
                "## Phase 2: Identify Trigger Path",
                f"- The vulnerable function is `{func_name}`",
                "- Trace the call chain to identify what input reaches this function",
                "- Note: if this is a server, start it in background and send crafted requests.",
                "",
                "## Phase 3: Run with Crafted Input",
                "- Run the built binary with crafted input",
                "- Write a test script (test.sh) that runs the binary and checks output",
                '- Print "ARGUS_VALIDATED" if the vulnerability is confirmed',
                "",
                "## Phase 4: Verify",
                f"- Confirm that `{func_name}` was actually exercised",
                "- Check for panics, sanitizer output (if using nightly + ASAN), or incorrect behavior",
                "",
            ])

        return parts

    def _build_java_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Phased prompt for Java projects: maven/gradle build, run."""
        func_name = target.function.name
        build_hint = context.build_system_hint
        if build_hint == "gradle":
            build_cmd = "gradle build -x test"
        else:
            build_cmd = "mvn package -DskipTests"
        return [
            "## Phase 1: Explore and Build",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            f"- Build: {build_cmd}",
            "- Identify the output JAR/WAR and how the application is run",
            "",
            "## Phase 2: Identify Trigger Path",
            f"- The vulnerable function is `{func_name}`",
            "- Trace the call chain: is it reached via HTTP endpoint, CLI, or internal logic?",
            "",
            "## Phase 3: Run with Crafted Input",
            "- Start the application (java -jar target/*.jar &) and send crafted requests",
            "- Or run the CLI with crafted arguments",
            "- Write a test script (test.sh) that runs and checks output",
            '- Print "ARGUS_VALIDATED" if the vulnerability is confirmed',
            "",
            "## Phase 4: Verify",
            f"- Confirm that `{func_name}` was reached",
            "- Check for SQL errors, stack traces, unauthorized data access, or other evidence",
            "",
        ]

    def _build_generic_phases(
        self, finding: Finding, target: Target, context: ExploitContext,
    ) -> list[str]:
        """Fallback prompt for unknown languages."""
        func_name = target.function.name
        return [
            "## Phase 1: Explore and Build",
            "- Copy: cp -r /app/target /app/work/src && cd /app/work/src",
            "- Examine the project structure and determine how to build/run it",
            "- Install dependencies and build the project",
            "",
            "## Phase 2: Identify Trigger Path",
            f"- The vulnerable function is `{func_name}`",
            "- Trace the call chain to identify what input reaches this function",
            "",
            "## Phase 3: Run with Crafted Input",
            "- Run the application/binary with crafted input that exercises the vulnerable function",
            "- Write a test script (test.sh) that automates this",
            '- Print "ARGUS_VALIDATED" if the vulnerability is confirmed',
            "",
        ]

    def _build_common_footer(self, context: ExploitContext) -> list[str]:
        """Instructions shared by all prompts."""
        max_turns = self.config.claw_max_turns_build
        return [
            "## Instructions",
            "- Your working directory is /app/work (writable). Target source is at /app/target (read-only).",
            "- Copy the target into /app/work/src to build it (do NOT write to /app/target).",
            "- You MUST build and run the real project. DO NOT write standalone PoC/exploit code.",
            "- If a build dependency is missing, install it (apt-get install, pip install, npm install) and retry.",
            "- If the build fails, read errors carefully, fix the issue, and retry.",
            "- Save your test script as /app/work/test.sh so it can be extracted for reproducibility.",
            f"- You have up to {max_turns} tool-use turns.",
            "- Focus on reaching the vulnerable function through normal project entry points.",
        ]

    async def _ensure_image(self, language: str) -> str:
        """Build or retrieve the Claw Docker image with enriched build toolchain.

        Uses a lock to prevent concurrent builds of the same image
        when multiple validation tasks run in parallel.
        """
        from prowl.sandbox.images import compute_build_image_tag

        tag = f"prowl-claw-build-{language}-" + compute_build_image_tag(language)

        if tag in self._image_cache:
            return tag

        dockerfile = self._get_claw_dockerfile(language)
        await asyncio.to_thread(self._build_image_locked, tag, dockerfile)
        return tag

    def _build_image_locked(self, tag: str, dockerfile_content: str) -> None:
        """Build image with lock to prevent concurrent builds."""
        with self._image_build_lock:
            if tag in self._image_cache:
                return
            self._build_image(tag, dockerfile_content)
            self._image_cache[tag] = True

    def _get_claw_dockerfile(self, language: str) -> str:
        """Generate multi-stage Dockerfile: build Claw from source, then copy into
        an enriched runtime image with full build toolchain for the target language.

        Stage 1 builds Claw as a static musl binary (same for all languages).
        Stage 2 uses the enriched build-project image for the target language.
        """
        from prowl.sandbox.images import get_build_project_dockerfile

        # Stage 1: build Claw as a static musl binary so it runs on any Linux
        # base image regardless of GLIBC version.
        build_stage = """\
# Stage 1: build Claw Code from source (static musl binary)
FROM rust:latest AS claw-builder
RUN apt-get update && apt-get install -y git musl-tools pkg-config && rm -rf /var/lib/apt/lists/*
RUN rustup target add $(uname -m)-unknown-linux-musl
ENV OPENSSL_STATIC=1
RUN git clone --depth 1 https://github.com/ultraworkers/claw-code /build/claw-code
WORKDIR /build/claw-code/rust
RUN cargo build --release --target $(uname -m)-unknown-linux-musl -p rusty-claude-cli \
    && cp target/$(uname -m)-unknown-linux-musl/release/claw /build/claw
"""
        # Stage 2: enriched runtime with full build toolchain
        runtime_dockerfile = get_build_project_dockerfile(language)
        # Inject the COPY and ca-certificates after the base image RUN layer
        return build_stage + f"""
# Stage 2: enriched runtime with Claw
{runtime_dockerfile}
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/* || true
COPY --from=claw-builder /build/claw /usr/local/bin/claw
"""

    def _build_image(self, tag: str, dockerfile_content: str) -> None:
        """Build Docker image (runs in thread)."""
        client = self._get_docker_client()
        build_dir = Path(tempfile.mkdtemp(prefix="prowl-claw-build-"))
        try:
            (build_dir / "Dockerfile").write_text(dockerfile_content)
            client.images.build(path=str(build_dir), tag=tag, rm=True)
        except Exception as e:
            logger.error("Failed to build Claw image %s: %s", tag, e)
            raise
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def _run_claw_container(
        self,
        image_tag: str,
        prompt: str,
        api_key_name: str,
        api_key_value: str,
        model: str,
        timeout: int,
    ) -> dict:
        """Run Claw inside a Docker container and capture output.

        Uses elevated resource limits for full-project builds.
        """
        import shlex

        client = self._get_docker_client()

        # Write prompt to a file to avoid shell argument length limits
        staging_dir = Path(tempfile.mkdtemp(prefix="prowl-claw-"))
        try:
            (staging_dir / "prompt.txt").write_text(prompt)

            # Copy target codebase
            if self.target_dir.is_dir():
                shutil.copytree(
                    self.target_dir,
                    staging_dir / "target",
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(
                        ".git", "node_modules", "__pycache__", ".prowl",
                    ),
                )

            model_flag = f"--model {shlex.quote(model)} " if model else ""
            command = (
                f'claw --output-format json {model_flag}'
                '--permission-mode danger-full-access '
                '"$(cat /app/work/prompt.txt)"'
            )

            container = client.containers.run(
                image_tag,
                command=f"sh -c '{command}'",
                volumes={
                    str(staging_dir): {"bind": "/app/work", "mode": "rw"},
                    str(staging_dir / "target"): {"bind": "/app/target", "mode": "ro"},
                },
                working_dir="/app/work",
                environment={api_key_name: api_key_value},
                detach=True,
                # Elevated resource limits for full-project builds
                network_mode="bridge",
                mem_limit=self.sandbox_config.mem_limit_build,
                cpu_quota=self.sandbox_config.cpu_quota_build,
                pids_limit=1024,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                tmpfs={"/tmp": "size=1g,exec"},
            )

            try:
                result = container.wait(timeout=timeout)
                stdout = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )
                exit_code = result.get("StatusCode", -1)
            except Exception:
                container.kill()
                stdout = ""
                stderr = "Claw container timed out"
                exit_code = -1
            finally:
                container.remove(force=True)

            # Extract test script (the reproducible artifact)
            test_script = ""
            for name in ("test.sh", "test.py", "run_test.sh"):
                test_file = staging_dir / name
                if test_file.exists():
                    test_script = test_file.read_text(errors="replace")
                    break
            # Also search recursively in staging dir
            if not test_script:
                for p in staging_dir.rglob("test.*"):
                    if p.is_file() and p.suffix in (".sh", ".py", ".js"):
                        test_script = p.read_text(errors="replace")
                        break

            # Extract build log if present
            build_log = ""
            for name in ("build.log", "build_output.txt"):
                log_file = staging_dir / name
                if log_file.exists():
                    build_log = log_file.read_text(errors="replace")[:5000]
                    break

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "test_script": test_script,
                "build_log": build_log,
            }
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def _parse_result(self, finding: Finding, result: dict) -> ValidationOutcome:
        """Parse Claw container output into a ValidationOutcome."""
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", -1)
        test_script = result.get("test_script", "")
        build_log = result.get("build_log", "")

        # Check for sanitizer output (ASAN/UBSAN/MSAN) in stderr and stdout
        sanitizer = parse_sanitizer_output(stderr)
        if not sanitizer:
            sanitizer = parse_sanitizer_output(stdout)

        # Use the standard result checker with target function name
        status = check_result(
            finding.category,
            stdout,
            stderr,
            exit_code,
            sanitizer_output=sanitizer,
            target_function=finding.function_name,
        )

        # Check for our confirmation markers (ARGUS_VALIDATED or legacy ARGUS_POC_CONFIRMED)
        if "ARGUS_VALIDATED" in stdout or "ARGUS_POC_CONFIRMED" in stdout:
            status = ValidationStatus.CONFIRMED

        # Determine success evidence
        evidence = ""
        if sanitizer:
            # Check if the target function appears in the sanitizer trace
            sanitizer_details = sanitizer.get("details", "")
            if finding.function_name and finding.function_name in sanitizer_details:
                evidence = f"asan_target_function:{finding.function_name}"
            else:
                evidence = "asan"
        elif "ARGUS_VALIDATED" in stdout:
            evidence = "marker"
        elif "ARGUS_POC_CONFIRMED" in stdout:
            evidence = "marker"

        # Try to parse Claw's JSON output for metadata
        iterations_used = 1
        try:
            claw_output = json.loads(stdout)
            if isinstance(claw_output, dict):
                iterations_used = claw_output.get("num_turns", 1)
        except (json.JSONDecodeError, ValueError):
            pass

        return ValidationOutcome(
            status=status,
            poc_code=test_script,  # test script is the reproducible artifact
            test_script=test_script,
            build_log=build_log,
            stdout=stdout[:2000],
            stderr=stderr[:2000],
            exit_code=exit_code,
            sanitizer_output=sanitizer,
            iterations_used=iterations_used,
            success_evidence=evidence,
        )
