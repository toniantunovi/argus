"""Layer 2 triage engine."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import anyio

from prowl.context_builder.builder import ContextBuilder
from prowl.llm.budget import TokenBudget
from prowl.models.core import Severity, Target
from prowl.models.finding import Classification, Finding
from prowl.models.hypothesis import Hypothesis

if TYPE_CHECKING:
    from prowl.llm.sampling import LLMClient

logger = logging.getLogger(__name__)


class TriageEngine:
    """Run Layer 2 triage on promoted findings and batched hypotheses."""

    def __init__(
        self,
        llm_client: LLMClient,
        context_builder: ContextBuilder,
        budget: TokenBudget,
        targets_by_func: dict[str, Target] | None = None,
        max_concurrent: int = 4,
    ):
        self.llm = llm_client
        self.context_builder = context_builder
        self.budget = budget
        self.targets = targets_by_func or {}
        self.limiter = anyio.CapacityLimiter(max_concurrent)

    async def run(self, findings: list[Finding]) -> list[Finding]:
        """Triage all findings. Returns updated findings with classifications."""
        async with anyio.create_task_group() as tg:
            for finding in findings:
                tg.start_soon(self._triage_finding, finding)
        return findings

    async def run_batch(
        self, hypotheses: list[Hypothesis], target: Target
    ) -> list[Finding]:
        """Batch triage for mid-confidence hypotheses."""
        # Build contexts for all hypotheses
        contexts = []
        for hyp in hypotheses:
            ctx = self.context_builder.build_finding_context(
                target, hyp.title, hyp.description, hyp.category
            )
            contexts.append(ctx)

        estimated_tokens = 8000
        if not await self.budget.reserve(estimated_tokens):
            logger.warning("Budget exhausted for batch triage")
            return []

        try:
            results = await self.llm.batch_triage(contexts)
            findings = []
            for hyp, result in zip(hypotheses, results):
                finding = Finding.from_hypothesis(hyp, target.function)
                _apply_triage_result(finding, result)
                findings.append(finding)
            await self.budget.commit(estimated_tokens, estimated_tokens)
            return findings
        except Exception as e:
            logger.error("Batch triage failed: %s", e)
            await self.budget.release(estimated_tokens)
            return []

    async def _triage_finding(self, finding: Finding, _retries: int = 2) -> None:
        async with self.limiter:
            target = self._find_target(finding)
            if target is None:
                return

            last_error: Exception | None = None
            for attempt in range(_retries + 1):
                estimated_tokens = 7500
                if not await self.budget.reserve(estimated_tokens):
                    logger.warning(
                        "Budget exhausted, skipping triage for %s", finding.finding_id
                    )
                    return
                try:
                    context = self.context_builder.build_finding_context(
                        target,
                        finding.title,
                        finding.description,
                        finding.category,
                    )
                    result = await self.llm.triage(context)
                    _apply_triage_result(finding, result)
                    await self.budget.commit(estimated_tokens, estimated_tokens)
                    return
                except Exception as e:
                    last_error = e
                    await self.budget.release(estimated_tokens)
                    if attempt < _retries:
                        logger.warning(
                            "Triage attempt %d failed for %s: %s (retrying)",
                            attempt + 1, finding.finding_id, e,
                        )
                    else:
                        logger.error("Triage failed for %s after %d attempts: %s",
                                     finding.finding_id, _retries + 1, last_error)

    def _find_target(self, finding: Finding) -> Target | None:
        """Look up the Target that corresponds to a Finding."""
        for _tid, target in self.targets.items():
            if (
                target.function.name == finding.function_name
                and str(target.function.file_path) == finding.file_path
            ):
                return target
        return None


def _apply_triage_result(finding: Finding, result: dict) -> None:
    """Apply triage result dict to a Finding, updating classification and fields."""
    classification_str = result.get("classification", "uncertain")
    try:
        finding.classification = Classification(classification_str)
    except ValueError:
        finding.classification = Classification.UNCERTAIN

    severity_str = result.get("severity", finding.severity.value)
    try:
        finding.severity = Severity(severity_str)
    except ValueError:
        pass

    finding.confidence = result.get("confidence", finding.confidence)
    if "reasoning" in result:
        finding.reasoning = result["reasoning"]
    if "attack_path" in result:
        finding.attack_scenario = result["attack_path"]
