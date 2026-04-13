"""Claw Code agentic validation backend."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import threading
from pathlib import Path

from argus.config import LLMConfig, SandboxConfig, ValidationConfig
from argus.models.core import SignalCategory, Target
from argus.models.context import ExploitContext
from argus.models.finding import Finding
from argus.models.poc import ValidationStatus
from argus.sandbox.instrumentation import parse_sanitizer_output
from argus.validation.result_checker import check_result

from pydantic import BaseModel


class ValidationOutcome(BaseModel):
    """Result of a Claw validation attempt."""
    status: ValidationStatus
    poc_code: str = ""
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
        """Get wall-clock timeout based on finding category."""
        if finding.category == SignalCategory.MEMORY:
            return self.config.claw_timeout_memory
        return self.config.claw_timeout_default

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
        """Build the task prompt for Claw Code."""
        parts = [
            "You are inside a Docker container with the target C/C++ codebase at /app/target.",
            "Your task: write, compile, and run a proof-of-concept that demonstrates the following vulnerability.\n",
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

        # Success criteria based on category
        if finding.category == SignalCategory.MEMORY:
            parts.extend([
                "## Success Criteria",
                "1. Write your PoC as a C file that #includes or links against the vulnerable code in /app/target",
                "2. Compile with: gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g -o poc poc.c -I/app/target $(find /app/target -name '*.c' -not -name 'poc.c' | head -20)",
                "3. Run: ./poc",
                "4. ASAN/UBSAN must report a violation (heap-buffer-overflow, use-after-free, integer-overflow, etc.)",
                '5. After running the PoC, if ASAN fires, print "ARGUS_POC_CONFIRMED" to stdout',
                "",
            ])
        else:
            parts.extend([
                "## Success Criteria",
                "1. Write a self-contained PoC that demonstrates the vulnerability",
                "2. The PoC must produce observable evidence of the vulnerability on stdout",
                '3. Print "ARGUS_POC_CONFIRMED" to stdout if the vulnerability is demonstrated',
                "",
            ])

        parts.extend([
            "## Instructions",
            "- Your working directory is /app/work (writable). Target source is at /app/target (read-only).",
            "- Write all PoC files in /app/work. Do NOT write to /app/target.",
            "- Explore /app/target to understand the codebase structure first",
            "- Your PoC MUST compile against the actual target source — do not rewrite the vulnerable function",
            "- If compilation fails, read the error, fix it, and retry",
            "- If the vulnerability does not trigger, analyze why and adjust your approach",
            f"- You have up to {self.config.claw_max_turns} tool-use turns",
            "- Focus on triggering the bug, not on writing a clean exploit",
        ])

        return "\n".join(parts)

    async def _ensure_image(self, language: str) -> str:
        """Build or retrieve the Claw Docker image.

        Uses a lock to prevent concurrent builds of the same image
        when multiple validation tasks run in parallel.
        """
        from argus.sandbox.images import compute_image_tag

        tag = f"argus-claw-{language}-" + compute_image_tag(language, "claw")

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
        """Generate multi-stage Dockerfile: build Claw from source, then copy into runtime image.

        Claw Code is build-from-source only (no pre-built binaries).
        Stage 1 clones the repo and builds with cargo.
        Stage 2 copies the binary into a lean runtime image.
        """
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
        if language in ("c", "cpp"):
            return build_stage + """
# Stage 2: C/C++ runtime with ASAN + Claw
FROM gcc:13
RUN apt-get update && apt-get install -y \\
    libasan8 libubsan1 make cmake pkg-config \\
    ca-certificates git \\
    && rm -rf /var/lib/apt/lists/*
COPY --from=claw-builder /build/claw /usr/local/bin/claw
WORKDIR /app
"""
        # Fallback for other languages
        return build_stage + """
# Stage 2: Python runtime with Claw
FROM python:3.12-slim
RUN apt-get update && apt-get install -y ca-certificates git gcc g++ make \\
    && rm -rf /var/lib/apt/lists/*
COPY --from=claw-builder /build/claw /usr/local/bin/claw
WORKDIR /app
"""

    def _build_image(self, tag: str, dockerfile_content: str) -> None:
        """Build Docker image (runs in thread)."""
        client = self._get_docker_client()
        build_dir = Path(tempfile.mkdtemp(prefix="argus-claw-build-"))
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
        """Run Claw inside a Docker container and capture output."""
        import shlex

        client = self._get_docker_client()

        # Write prompt to a file to avoid shell argument length limits
        staging_dir = Path(tempfile.mkdtemp(prefix="argus-claw-"))
        try:
            (staging_dir / "prompt.txt").write_text(prompt)

            # Copy target codebase
            if self.target_dir.is_dir():
                shutil.copytree(
                    self.target_dir,
                    staging_dir / "target",
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(
                        ".git", "node_modules", "__pycache__", ".argus",
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
                # Security policy — relaxed for Claw
                network_mode="bridge",
                mem_limit=self.sandbox_config.mem_limit,
                cpu_quota=self.sandbox_config.cpu_quota,
                pids_limit=512,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                tmpfs={"/tmp": "size=256m,exec"},
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

            # Check if Claw wrote a PoC file
            poc_code = ""
            for ext in (".c", ".py", ".js", ".go"):
                poc_file = staging_dir / "work" / f"poc{ext}"
                if poc_file.exists():
                    poc_code = poc_file.read_text(errors="replace")
                    break
            # Also check /app/work for any .c files Claw created
            for p in (staging_dir).rglob("poc*"):
                if p.is_file() and p.suffix in (".c", ".cpp", ".py", ".js"):
                    poc_code = p.read_text(errors="replace")
                    break

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "poc_code": poc_code,
            }
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def _parse_result(self, finding: Finding, result: dict) -> ValidationOutcome:
        """Parse Claw container output into a ValidationOutcome."""
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", -1)
        poc_code = result.get("poc_code", "")

        # Check for sanitizer output
        sanitizer = parse_sanitizer_output(stderr)

        # Use the standard result checker
        status = check_result(
            finding.category,
            stdout,
            stderr,
            exit_code,
            sanitizer_output=sanitizer,
        )

        # Also check for our confirmation marker
        if "ARGUS_POC_CONFIRMED" in stdout:
            status = ValidationStatus.CONFIRMED

        # Try to parse Claw's JSON output for metadata
        iterations_used = 1
        try:
            # Claw's --output-format json wraps output in a JSON object
            claw_output = json.loads(stdout)
            if isinstance(claw_output, dict):
                iterations_used = claw_output.get("num_turns", 1)
        except (json.JSONDecodeError, ValueError):
            pass

        return ValidationOutcome(
            status=status,
            poc_code=poc_code,
            stdout=stdout[:2000],
            stderr=stderr[:2000],
            exit_code=exit_code,
            sanitizer_output=sanitizer,
            iterations_used=iterations_used,
            success_evidence="asan" if sanitizer else ("marker" if "ARGUS_POC_CONFIRMED" in stdout else ""),
        )
