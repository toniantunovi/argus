"""Layer 1 hypothesis engine - parallel hypothesis generation."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import anyio

from argus.context_builder.builder import ContextBuilder
from argus.llm.budget import TokenBudget
from argus.models.core import Target
from argus.models.finding import Finding
from argus.models.hypothesis import ConfidenceGate, Hypothesis

if TYPE_CHECKING:
    from argus.llm.sampling import LLMClient

logger = logging.getLogger(__name__)


class HypothesisStats:
    """Tracks per-target success/failure counts from Layer 1."""

    def __init__(self) -> None:
        self.scanned: int = 0
        self.llm_errors: int = 0
        self.budget_exhausted: int = 0


class HypothesisEngine:
    """Run Layer 1 hypothesis generation across all targets in parallel."""

    def __init__(
        self,
        llm_client: LLMClient,
        context_builder: ContextBuilder,
        budget: TokenBudget,
        gate: ConfidenceGate | None = None,
        max_concurrent: int = 8,
        max_promoted: int | None = None,
    ):
        self.llm = llm_client
        self.context_builder = context_builder
        self.budget = budget
        self.gate = gate or ConfidenceGate()
        self.limiter = anyio.CapacityLimiter(max_concurrent)
        self.max_promoted = max_promoted

    async def run(
        self, targets: list[Target]
    ) -> tuple[list[Finding], list[Hypothesis], list[Hypothesis], HypothesisStats]:
        """Run Layer 1 on all targets.

        Returns:
            (promoted_findings, batch_hypotheses, suppressed_hypotheses, stats)
        """
        promoted: list[Finding] = []
        batched: list[Hypothesis] = []
        suppressed: list[Hypothesis] = []
        all_target_hyps: list[tuple[Target, Hypothesis]] = []
        stats = HypothesisStats()

        async with anyio.create_task_group() as tg:
            for target in targets:
                tg.start_soon(self._process_target, target, all_target_hyps, stats)

        # Gate all hypotheses
        for target, hyp in all_target_hyps:
            action = self.gate.classify(hyp)
            if action == "promote":
                finding = Finding.from_hypothesis(hyp, target.function)
                promoted.append(finding)
            elif action == "batch":
                batched.append(hyp)
            else:
                suppressed.append(hyp)

        # Cap promoted findings — keep highest confidence
        if self.max_promoted is not None and len(promoted) > self.max_promoted:
            promoted.sort(key=lambda f: f.confidence, reverse=True)
            dropped = len(promoted) - self.max_promoted
            promoted = promoted[:self.max_promoted]
            logger.info(
                "Capped promoted findings to %d (dropped %d lower-confidence findings)",
                self.max_promoted, dropped,
            )

        logger.info(
            "Layer 1 complete: %d promoted, %d batched, %d suppressed "
            "(%d scanned, %d LLM errors, %d budget-skipped)",
            len(promoted),
            len(batched),
            len(suppressed),
            stats.scanned,
            stats.llm_errors,
            stats.budget_exhausted,
        )
        return promoted, batched, suppressed, stats

    async def _process_target(
        self, target: Target, results: list[tuple[Target, Hypothesis]], stats: HypothesisStats,
    ) -> None:
        async with self.limiter:
            estimated_tokens = 5000  # ~4000 input + ~1000 output
            if not await self.budget.reserve(estimated_tokens):
                logger.warning("Budget exhausted, skipping %s", target.function.name)
                stats.budget_exhausted += 1
                return
            try:
                context = self.context_builder.build_hypothesis_context(target)
                response = await self.llm.hypothesize(context)
                for hyp in response.hypotheses:
                    results.append((target, hyp))
                await self.budget.commit(estimated_tokens, estimated_tokens)
                stats.scanned += 1
            except Exception as e:
                import traceback
                logger.error(
                    "Hypothesis generation failed for %s: [%s] %s\n%s",
                    target.function.name,
                    type(e).__name__,
                    e,
                    traceback.format_exc(),
                )
                stats.llm_errors += 1
                await self.budget.release(estimated_tokens)
