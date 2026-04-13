"""Sandbox container lifecycle management."""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from argus.config import SandboxConfig
from argus.sandbox.images import compute_image_tag, get_dockerfile
from argus.sandbox.instrumentation import get_compile_flags, parse_sanitizer_output
from argus.sandbox.policy import SandboxPolicy

logger = logging.getLogger(__name__)


class SandboxManager(Protocol):
    """Protocol for sandbox management - allows mocking."""
    async def execute_poc(self, poc_code: str, language: str, target_dir: Path, timeout: int = 30) -> dict: ...


class DockerSandboxManager:
    """Docker-based sandbox for PoC execution."""

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self.policy = SandboxPolicy.from_config(self.config)
        self._client = None
        self._image_cache: dict[str, bool] = {}

    def _get_client(self):
        if self._client is None:
            import docker
            self._client = docker.from_env()
        return self._client

    async def execute_poc(
        self,
        poc_code: str,
        language: str,
        target_dir: Path,
        timeout: int | None = None,
        instrumentation: list[str] | None = None,
    ) -> dict:
        """Execute a PoC in a sandboxed container.

        Returns dict with: stdout, stderr, exit_code, sanitizer_output
        """
        timeout = timeout or self.config.timeout_default

        # Build or get cached image
        image_tag = await self._ensure_image(language, target_dir)

        # Create temp dir with PoC and target code
        staging_dir = Path(tempfile.mkdtemp(prefix="argus-poc-"))
        try:
            # Copy target code
            target_dest = staging_dir / "target"
            if target_dir.is_dir():
                shutil.copytree(target_dir, target_dest)

            # Write PoC
            poc_ext = {
                "python": ".py",
                "javascript": ".js",
                "c": ".c",
                "go": ".go",
                "java": ".java",
                "rust": ".rs",
            }.get(language, ".py")
            poc_path = staging_dir / f"poc{poc_ext}"
            poc_path.write_text(poc_code)

            # Build compile+run command
            run_cmd = self._build_run_command(language, poc_ext, instrumentation or [])

            # Run in container
            result = await asyncio.to_thread(
                self._run_container, image_tag, staging_dir, run_cmd, timeout
            )

            # Parse sanitizer output
            sanitizer = parse_sanitizer_output(result.get("stderr", ""))
            if sanitizer:
                result["sanitizer_output"] = sanitizer

            return result
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    async def _ensure_image(self, language: str, target_dir: Path) -> str:
        """Build or retrieve cached Docker image."""
        lockfile_content = ""
        for lockfile in ["requirements.txt", "package-lock.json", "go.sum", "Cargo.lock"]:
            p = target_dir / lockfile
            if p.exists():
                lockfile_content = p.read_text(errors="ignore")
                break

        tag = compute_image_tag(language, lockfile_content)

        if tag in self._image_cache:
            return tag

        dockerfile_content = get_dockerfile(language)

        # Build image
        await asyncio.to_thread(self._build_image, tag, dockerfile_content, target_dir)
        self._image_cache[tag] = True
        return tag

    def _build_image(self, tag: str, dockerfile_content: str, context_dir: Path) -> None:
        """Build Docker image (runs in thread)."""
        client = self._get_client()
        build_dir = Path(tempfile.mkdtemp(prefix="argus-build-"))
        try:
            (build_dir / "Dockerfile").write_text(dockerfile_content)
            # Copy target files for context
            if context_dir.is_dir():
                shutil.copytree(context_dir, build_dir / "target", dirs_exist_ok=True)
            client.images.build(path=str(build_dir), tag=tag, rm=True)
        except Exception as e:
            logger.error(f"Failed to build image {tag}: {e}")
            raise
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def _run_container(self, image_tag: str, staging_dir: Path, command: str, timeout: int) -> dict:
        """Run container and capture output (runs in thread)."""
        client = self._get_client()
        docker_kwargs = self.policy.to_docker_kwargs()

        try:
            container = client.containers.run(
                image_tag,
                command=f"sh -c '{command}'",
                volumes={str(staging_dir): {"bind": "/app/poc", "mode": "ro"}},
                working_dir="/app/poc",
                detach=True,
                **docker_kwargs,
            )

            try:
                result = container.wait(timeout=timeout)
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                exit_code = result.get("StatusCode", -1)
            except Exception:
                container.kill()
                stdout = ""
                stderr = "Container execution timed out"
                exit_code = -1
            finally:
                container.remove(force=True)

            return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _build_run_command(self, language: str, poc_ext: str, instrumentation: list[str]) -> str:
        """Build the command to compile (if needed) and run the PoC."""
        if language == "python":
            return f"python3 poc{poc_ext}"
        elif language in ("javascript", "typescript"):
            return f"node poc{poc_ext}"
        elif language == "c":
            flags = get_compile_flags(instrumentation) if instrumentation else ""
            return f"gcc {flags} -o poc poc{poc_ext} && ./poc"
        elif language == "cpp":
            flags = get_compile_flags(instrumentation) if instrumentation else ""
            return f"g++ {flags} -o poc poc{poc_ext} && ./poc"
        elif language == "go":
            return f"go run poc{poc_ext}"
        elif language == "java":
            return f"javac poc{poc_ext} && java poc"
        elif language == "rust":
            return f"rustc poc{poc_ext} -o poc && ./poc"
        return f"python3 poc{poc_ext}"
