"""Chain analysis: deterministic grouping + LLM evaluation."""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from prowl.models.chain import Chain, ChainComponent, ChainType
from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Classification, Finding
from prowl.recon.call_graph import CallGraph
from prowl.rubrics.loader import load_rubric

if TYPE_CHECKING:
    from prowl.llm.sampling import LLMClient

logger = logging.getLogger(__name__)


class ChainAnalyzer:
    """Group related findings and evaluate potential attack chains via LLM."""

    def __init__(self, llm_client: LLMClient, call_graph: CallGraph):
        self.llm = llm_client
        self.call_graph = call_graph

    async def analyze(self, findings: list[Finding]) -> list[Chain]:
        """Group findings and evaluate potential chains."""
        # Step 1: Deterministic grouping
        groups = self._group_findings(findings)

        if not groups:
            return []

        # Step 2: LLM evaluation of each group
        chains: list[Chain] = []
        for group_id, group_findings in groups.items():
            if len(group_findings) < 2:
                continue
            chain = await self._evaluate_chain(group_id, group_findings)
            if chain and chain.chain_type is not None:
                chains.append(chain)

        return chains

    # ------------------------------------------------------------------
    # Deterministic grouping
    # ------------------------------------------------------------------

    def _group_findings(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Deterministic grouping by proximity criteria."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        exploitable_findings = [
            f
            for f in findings
            if f.classification in (Classification.EXPLOITABLE, Classification.UNCERTAIN)
        ]

        # Group by same function
        by_func: dict[str, list[Finding]] = defaultdict(list)
        for f in exploitable_findings:
            by_func[f"{f.file_path}::{f.function_name}"].append(f)
        for key, group in by_func.items():
            if len(group) >= 2:
                groups[f"func:{key}"] = group

        # Group by same file + within 3 call graph hops
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in exploitable_findings:
            by_file[f.file_path].append(f)

        for file_path, file_findings in by_file.items():
            if len(file_findings) < 2:
                continue
            # Check pairwise if within 3 hops
            for i, f1 in enumerate(file_findings):
                for f2 in file_findings[i + 1 :]:
                    id1 = f"{f1.file_path}::{f1.function_name}"
                    id2 = f"{f2.file_path}::{f2.function_name}"
                    hops = self.call_graph.hops_between(id1, id2, max_hops=3)
                    if hops is not None:
                        group_key = f"proximity:{f1.finding_id}+{f2.finding_id}"
                        groups[group_key] = [f1, f2]

        # Group by same category (for related findings)
        by_cat: dict[str, list[Finding]] = defaultdict(list)
        for f in exploitable_findings:
            by_cat[f.category.value].append(f)
        # (category groups are available but not automatically added to groups
        # to avoid noise -- the func and proximity groups are more meaningful)

        return dict(groups)

    # ------------------------------------------------------------------
    # LLM-based chain evaluation
    # ------------------------------------------------------------------

    async def _evaluate_chain(
        self, group_id: str, findings: list[Finding]
    ) -> Chain | None:
        """LLM evaluation of a potential chain."""
        try:
            # Load chain rules from YAML
            rubric = self._load_chain_rubric()

            result = await self.llm.evaluate_chain(findings, rubric)

            if not result.get("is_chain", False):
                return None

            chain_type = None
            ct = result.get("chain_type")
            if ct:
                try:
                    chain_type = ChainType(ct)
                except ValueError:
                    pass

            severity = Severity.HIGH
            sev = result.get("combined_severity")
            if sev:
                try:
                    severity = Severity(sev)
                except ValueError:
                    pass

            components = [
                ChainComponent(finding_id=f.finding_id, role=f.title)
                for f in findings
            ]

            chain = Chain(
                chain_id=group_id,
                chain_type=chain_type,
                components=components,
                combined_severity=severity,
                description=result.get("description", ""),
                reasoning=result.get("reasoning", ""),
            )

            # Update findings with chain info
            for f in findings:
                f.chain_id = group_id
                f.chain_severity = severity

            return chain
        except Exception as e:
            logger.error("Chain evaluation failed for %s: %s", group_id, e)
            return None

    @staticmethod
    def _load_chain_rubric() -> str:
        """Load chain rules from the built-in chain_rules.yml rubric."""
        chain_rules_path = (
            Path(__file__).parent.parent / "rubrics" / "chains" / "chain_rules.yml"
        )
        if chain_rules_path.exists():
            with open(chain_rules_path) as f:
                data = yaml.safe_load(f) or {}
            rules = data.get("chain_rules", [])
            return "\n".join(
                f"- {r['name']}: {r['instruction']}" for r in rules
            )
        # Fallback: use the generic rubric loader
        return load_rubric("chains", [SignalCategory.AUTH])
