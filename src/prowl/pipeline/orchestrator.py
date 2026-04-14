"""Full scan pipeline orchestrator: recon -> L1 -> L2 -> L3."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from prowl.cache.cross_cutting import capture_state, check_cross_cutting_invalidation
from prowl.cache.store import CacheStore
from prowl.config import ArgusConfig, load_config
from prowl.context_builder.builder import ContextBuilder
from prowl.hypothesis.engine import HypothesisEngine
from prowl.hypothesis.gate import group_batched_hypotheses
from prowl.llm.budget import TokenBudget
from prowl.llm.sampling import LLMClient
from prowl.models.chain import Chain
from prowl.models.core import Function, ProjectType, Target
from prowl.models.finding import Classification, Finding
from prowl.models.output import Report
from prowl.models.scan import BudgetState, ScanProgress, ScanState, ScanStatus
from prowl.pipeline.resume import ScanStateManager
from prowl.recon.call_graph import build_call_graph
from prowl.recon.exclusions import collect_files
from prowl.recon.extractor import extract_functions
from prowl.recon.interaction import detect_interaction_targets
from prowl.recon.prioritizer import prioritize_targets
from prowl.recon.project_type import detect_project_type
from prowl.recon.scorer import score_functions
from prowl.recon.signals import detect_signals
from prowl.sandbox.manager import SandboxManager
from prowl.triage.chain_analyzer import ChainAnalyzer
from prowl.triage.classifier import filter_for_validation
from prowl.triage.engine import TriageEngine
from prowl.validation.engine import ValidationEngine

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(
        self,
        project_root: Path,
        llm_client: LLMClient,
        sandbox: SandboxManager,
        config: ArgusConfig | None = None,
    ):
        self.project_root = project_root
        self.llm = llm_client
        self.sandbox = sandbox
        self.config = config or load_config(project_root)

        # Initialize subsystems
        self.budget = TokenBudget(
            max_tokens=self.config.budget.max_tokens_per_scan,
            layer3_fraction=self.config.budget.layer3_budget_fraction,
        )
        self.cache = CacheStore(project_root / ".prowl" / "cache")
        self.state_manager = ScanStateManager(Path(self.config.resume.state_dir))

        # Will be set during scan
        self.functions: dict[str, Function] = {}
        self.targets: list[Target] = []
        self.call_graph = None
        self.context_builder = None

    async def run(self, resume: bool = False, scan_id: str | None = None, categories: list[str] | None = None) -> Report:
        """Execute full scan pipeline."""
        start_time = time.time()
        scan_id = scan_id or str(uuid.uuid4())[:8]

        progress = ScanProgress(
            scan_id=scan_id,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            budget=BudgetState(
                max_tokens=self.config.budget.max_tokens_per_scan,
                max_cost=self.config.budget.max_cost_per_scan,
                layer3_budget_fraction=self.config.budget.layer3_budget_fraction,
            ),
        )

        state = ScanState(progress=progress)

        # Check for resume
        if resume:
            prev_state = self.state_manager.load_state(scan_id)
            if prev_state:
                state = prev_state
                state.progress.status = ScanStatus.RESUMED
                state.progress.resumed_from = scan_id
                logger.info(f"Resuming scan {scan_id}")

        all_findings: list[Finding] = []
        all_chains: list[Chain] = []

        try:
            # === PHASE 1: RECONNAISSANCE ===
            if not state.recon_complete:
                logger.info("Starting reconnaissance...")
                self._run_recon(state, categories)
                state.recon_complete = True
                if self.config.resume.enabled:
                    self.state_manager.save_state(scan_id, state)

            if not self.targets:
                logger.info("No targets found above scoring threshold")
                progress.status = ScanStatus.COMPLETED
                progress.wall_time_seconds = time.time() - start_time
                return Report(scan_progress=progress, findings=[], chains=[])

            # Cross-cutting invalidation check
            if self.config.cache.cross_cutting_invalidation:
                prev_proj_state = self.cache.get("__project_state__")
                if prev_proj_state:
                    reasons = check_cross_cutting_invalidation(self.cache, self.project_root, prev_proj_state)
                    for reason in reasons:
                        logger.info(f"Cache invalidation: {reason}")
                current_proj_state = capture_state(self.project_root)
                self.cache.put("__project_state__", current_proj_state)

            # Verify LLM session is available before running LLM layers
            try:
                self.llm.check_session()
            except RuntimeError as e:
                logger.error("LLM session check failed: %s", e)
                progress.status = ScanStatus.FAILED
                progress.targets_skipped = len(self.targets)
                progress.skip_reasons.llm_error = len(self.targets)
                progress.wall_time_seconds = time.time() - start_time
                return Report(scan_progress=progress, findings=[])

            # === PHASE 2: HYPOTHESIS (Layer 1) ===
            logger.info(f"Running Layer 1 hypothesis on {len(self.targets)} targets...")
            hypothesis_engine = HypothesisEngine(
                self.llm, self.context_builder, self.budget,
                max_concurrent=self.config.concurrency.max_concurrent_hypotheses,
                max_promoted=self.config.scoring.max_promoted_findings,
            )
            promoted, batched, suppressed, hyp_stats = await hypothesis_engine.run(self.targets)
            all_findings.extend(promoted)
            progress.targets_scanned += hyp_stats.scanned
            progress.targets_skipped += hyp_stats.llm_errors + hyp_stats.budget_exhausted
            progress.skip_reasons.llm_error += hyp_stats.llm_errors
            progress.skip_reasons.budget_exhausted += hyp_stats.budget_exhausted
            progress.layers_completed.append("hypothesis")

            if self.config.resume.enabled:
                self.state_manager.save_state(scan_id, state)

            if self.budget.is_exhausted():
                logger.warning("Budget exhausted after Layer 1")
                progress.status = ScanStatus.PARTIAL
                progress.wall_time_seconds = time.time() - start_time
                return Report(scan_progress=progress, findings=all_findings)

            # === PHASE 3: TRIAGE (Layer 2) ===
            logger.info(f"Running Layer 2 triage on {len(all_findings)} findings...")
            targets_by_func = {t.function.identifier: t for t in self.targets}
            triage_engine = TriageEngine(
                self.llm, self.context_builder, self.budget,
                targets_by_func=targets_by_func,
                max_concurrent=self.config.concurrency.max_concurrent_triage,
            )
            await triage_engine.run(all_findings)

            # Batch triage for mid-confidence hypotheses
            if batched:
                groups = group_batched_hypotheses(batched, targets_by_func)
                for group_key, group_hyps in groups.items():
                    # Find a representative target for this group
                    for t in self.targets:
                        batch_findings = await triage_engine.run_batch(group_hyps[:8], t)
                        all_findings.extend(batch_findings)
                        break

            progress.layers_completed.append("triage")

            # === PHASE 3.5: CHAIN ANALYSIS ===
            if self.config.triage.chain_analysis:
                logger.info("Running chain analysis...")
                chain_analyzer = ChainAnalyzer(self.llm, self.call_graph)
                exploitable = [f for f in all_findings if f.classification in (Classification.EXPLOITABLE, Classification.UNCERTAIN)]
                all_chains = await chain_analyzer.analyze(exploitable)
                logger.info(f"Found {len(all_chains)} attack chains")

            if self.config.resume.enabled:
                self.state_manager.save_state(scan_id, state)

            # === PHASE 4: VALIDATION (Layer 3) ===
            if self.config.validation.enabled:
                to_validate = filter_for_validation(all_findings, self.config.validation.severity_gate)
                logger.info(f"Running Layer 3 validation on {len(to_validate)} findings...")
                validation_engine = ValidationEngine(
                    self.llm, self.sandbox, self.context_builder, self.budget,
                    config=self.config.validation,
                    target_dir=self.project_root,
                    max_concurrent=self.config.concurrency.max_concurrent_validations,
                )
                vstats = await validation_engine.run(to_validate, targets_by_func)
                if vstats.docker_unavailable:
                    logger.error(
                        "Layer 3 skipped entirely: %s",
                        vstats.errors[0] if vstats.errors else "Docker unavailable",
                    )
                    progress.skip_reasons.sandbox_failure += len(to_validate)
                else:
                    progress.layers_completed.append("validation")
                    if vstats.failed:
                        progress.skip_reasons.sandbox_failure += vstats.failed

            progress.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            progress.status = ScanStatus.FAILED
            if self.config.resume.enabled:
                self.state_manager.save_state(scan_id, state)

        progress.completed_at = datetime.now(timezone.utc)
        progress.wall_time_seconds = time.time() - start_time
        progress.budget.tokens_used = self.budget.used

        # Clean up state on successful completion
        if progress.status == ScanStatus.COMPLETED:
            self.state_manager.clean_state(scan_id)

        return Report(
            scan_progress=progress,
            findings=all_findings,
            chains=[c.model_dump() for c in all_chains],
        )

    def _run_recon(self, state: ScanState, categories: list[str] | None = None) -> None:
        """Run the reconnaissance phase (deterministic, no LLM)."""
        config = self.config

        # Collect files
        included_files, excluded_files = collect_files(
            self.project_root,
            config_include=config.scan.include or None,
            config_exclude=config.scan.exclude or None,
            auto_exclude=config.reconnaissance.auto_exclude,
            auto_exclude_override=config.reconnaissance.auto_exclude_override or None,
            languages=config.scan.languages or None,
        )
        state.progress.auto_excluded_paths = len(excluded_files)
        logger.info(f"Files: {len(included_files)} included, {len(excluded_files)} excluded")

        # Extract functions
        all_functions: list[Function] = []
        for file_path in included_files:
            try:
                funcs = extract_functions(file_path)
                all_functions.extend(funcs)
            except Exception as e:
                logger.warning(f"Parse failure for {file_path}: {e}")
                state.progress.skip_reasons.parse_failure += 1

        logger.info(f"Extracted {len(all_functions)} functions")

        # Detect signals
        for func in all_functions:
            signals = detect_signals(func)
            func.signals = signals

        # Detect project type
        project_type_str = config.scan.project_type
        if project_type_str == "auto":
            project_type = detect_project_type(self.project_root, all_functions)
        else:
            project_type = ProjectType(project_type_str)

        # Build call graph
        self.call_graph = build_call_graph(all_functions)

        # Populate caller/callee info
        for func in all_functions:
            func.callers = list(self.call_graph.callers.get(func.identifier, set()))
            func.callees = list(self.call_graph.calls.get(func.identifier, set()))

        # Score functions
        scores = score_functions(all_functions, project_type)

        # Detect interaction targets
        if config.reconnaissance.interaction_targets:
            interactions = detect_interaction_targets(all_functions)
            state.progress.interaction_targets_found = len(interactions)

        # Prioritize targets
        self.targets = prioritize_targets(
            all_functions, scores, self.call_graph,
            max_targets=config.reconnaissance.max_review_chunks,
        )
        state.progress.targets_total = len(self.targets)

        # Build function index and context builder
        self.functions = {f.identifier: f for f in all_functions}
        self.context_builder = ContextBuilder(self.functions, self.call_graph, str(self.project_root))

        logger.info(f"Recon complete: {len(self.targets)} targets above threshold")
