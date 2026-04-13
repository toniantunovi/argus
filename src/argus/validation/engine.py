"""Layer 3 validation engine — agentic PoC development via Claw Code."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import anyio

from argus.config import LLMConfig, SandboxConfig, ValidationConfig
from argus.context_builder.builder import ContextBuilder
from argus.llm.budget import TokenBudget
from argus.llm.sampling import LLMClient
from argus.models.core import SignalCategory, Target
from argus.models.finding import Classification, Finding
from argus.models.poc import ValidationStatus
from argus.sandbox.manager import SandboxManager
from argus.validation.claw_backend import ClawValidationBackend

logger = logging.getLogger(__name__)


@dataclass
class ValidationStats:
    """Summary of Layer 3 validation results."""
    attempted: int = 0
    confirmed: int = 0
    partial: int = 0
    failed: int = 0
    skipped: int = 0
    no_target: int = 0
    budget_exhausted: int = 0
    docker_unavailable: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def all_failed(self) -> bool:
        return self.attempted > 0 and self.confirmed == 0 and self.partial == 0


class ValidationEngine:
    def __init__(
        self,
        llm_client: LLMClient,
        sandbox: SandboxManager,
        context_builder: ContextBuilder,
        budget: TokenBudget,
        config: ValidationConfig | None = None,
        sandbox_config: SandboxConfig | None = None,
        llm_config: LLMConfig | None = None,
        target_dir: Path | None = None,
        max_concurrent: int = 2,
    ):
        self.context_builder = context_builder
        self.budget = budget
        self.config = config or ValidationConfig()
        self.target_dir = target_dir or Path(".")
        self.limiter = anyio.CapacityLimiter(max_concurrent)
        self.claw = ClawValidationBackend(
            config=self.config,
            sandbox_config=sandbox_config or SandboxConfig(),
            llm_config=llm_config or LLMConfig(),
            target_dir=self.target_dir,
        )

    async def run(self, findings: list[Finding], targets: dict[str, Target]) -> ValidationStats:
        """Run Layer 3 validation on findings. Returns summary stats."""
        stats = ValidationStats()

        # Pre-flight Docker check
        docker_err = self.claw.check_docker()
        if docker_err:
            stats.docker_unavailable = True
            stats.errors.append(f"Docker unavailable: {docker_err}")
            logger.error(
                "Layer 3 validation aborted: Docker is not available (%s). "
                "All %d findings will be skipped.",
                docker_err, len(findings),
            )
            return stats

        to_validate = findings[:self.config.max_exploits]

        async with anyio.create_task_group() as tg:
            for finding in to_validate:
                target = self._find_target(finding, targets)
                if target:
                    tg.start_soon(self._validate_finding, finding, target, stats)
                else:
                    stats.no_target += 1
                    logger.warning(
                        "Validation skipped for %s: could not match finding to a recon target "
                        "(function=%s, file=%s)",
                        finding.finding_id, finding.function_name, finding.file_path,
                    )

        # Log summary
        logger.info(
            "Layer 3 validation complete: %d attempted, %d confirmed, %d partial, "
            "%d failed, %d skipped, %d no-target-match",
            stats.attempted, stats.confirmed, stats.partial,
            stats.failed, stats.skipped, stats.no_target,
        )
        if stats.all_failed:
            logger.warning(
                "All %d validation attempts failed — no PoCs were confirmed. "
                "Check Docker connectivity, API keys, and Claw image builds.",
                stats.attempted,
            )

        return stats

    async def _validate_finding(self, finding: Finding, target: Target, stats: ValidationStats) -> None:
        """Validate a single finding via Claw Code."""
        async with self.limiter:
            estimated_tokens = 50000
            if not await self.budget.reserve(estimated_tokens):
                stats.budget_exhausted += 1
                logger.warning("Budget exhausted, skipping validation for %s", finding.finding_id)
                return

            context = self.context_builder.build_exploit_context(
                target, finding.category, finding.severity.value,
            )
            max_iter = self._get_max_iterations(finding)

            stats.attempted += 1
            finding.validation_attempted = True
            outcome = await self.claw.validate(finding, target, context, max_iter)

            # Map outcome onto finding — always preserve PoC code for reproducibility
            finding.iterations_used = outcome.iterations_used
            finding.validation_stdout = outcome.stdout or None
            finding.validation_stderr = outcome.stderr or None
            finding.sanitizer_output = outcome.sanitizer_output
            if outcome.poc_code:
                finding.poc_code = outcome.poc_code
            if outcome.status == ValidationStatus.CONFIRMED:
                stats.confirmed += 1
                finding.poc_validated = True
                finding.poc_code = outcome.poc_code
                finding.validation_method = outcome.success_evidence or "confirmed"
                finding.classification = Classification.EXPLOITABLE
                logger.info(
                    "PoC confirmed for %s in %d iterations",
                    finding.finding_id, outcome.iterations_used,
                )
            elif outcome.status == ValidationStatus.PARTIAL:
                stats.partial += 1
                finding.validation_method = "partial"
                logger.info(
                    "PoC partial for %s — vulnerability triggered but not fully confirmed",
                    finding.finding_id,
                )
            elif outcome.status == ValidationStatus.SKIPPED:
                stats.skipped += 1
                finding.validation_method = "skipped"
                logger.warning(
                    "Validation skipped for %s: %s",
                    finding.finding_id, outcome.success_evidence or outcome.stderr or "unknown reason",
                )
            elif outcome.status == ValidationStatus.FAILED:
                stats.failed += 1
                finding.validation_method = "failed"
                logger.warning(
                    "Validation failed for %s: %s",
                    finding.finding_id,
                    (outcome.stderr or "no error details")[:200],
                )

            await self.budget.commit(estimated_tokens, estimated_tokens)

    def _get_max_iterations(self, finding: Finding) -> int:
        if finding.category == SignalCategory.MEMORY:
            return self.config.max_iterations_memory
        if finding.category in (SignalCategory.CONCURRENCY, SignalCategory.FINANCIAL):
            return self.config.max_iterations_medium
        if finding.chain_id:
            return self.config.max_iterations_chain
        return self.config.max_iterations_simple

    def _find_target(self, finding: Finding, targets: dict[str, Target]) -> Target | None:
        for tid, target in targets.items():
            if target.function.name == finding.function_name and str(target.function.file_path) == finding.file_path:
                return target
        return None
