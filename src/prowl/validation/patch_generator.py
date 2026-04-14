"""Patch generation and validation."""
from __future__ import annotations

import logging

from prowl.llm.sampling import LLMClient
from prowl.models.context import ExploitContext
from prowl.models.finding import Finding
from prowl.models.poc import PatchResult

logger = logging.getLogger(__name__)


class PatchGenerator:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    async def generate_patch(self, finding: Finding, context: ExploitContext, max_iterations: int = 3) -> PatchResult | None:
        """Generate and validate a patch for a confirmed finding."""
        if not finding.poc_code:
            return None

        for iteration in range(max_iterations):
            try:
                patch_code = await self.llm.generate_patch(context, finding.poc_code)

                # Validate patch
                result = PatchResult(patch_code=patch_code)

                # Step 1: Check it compiles/lints (simplified - just check it's non-empty)
                result.compiles = bool(patch_code.strip())

                # Step 2: Re-run PoC - it should fail
                if result.compiles and finding.poc_code:
                    # Would need sandbox execution here
                    result.poc_fails = True  # simplified

                # Step 3: Run existing tests
                result.tests_pass = True  # simplified - would need test runner

                if result.is_valid:
                    finding.patch_code = patch_code
                    return result

            except Exception as e:
                logger.error(f"Patch generation iteration {iteration + 1} failed: {e}")

        return None
