"""Integration test for the scan orchestrator with mocks."""
from pathlib import Path

import pytest

from argus.config import ArgusConfig
from argus.models.output import Report
from argus.models.scan import ScanStatus
from argus.pipeline.orchestrator import ScanOrchestrator

from tests.conftest import MockLLMClient, MockSandboxManager


class TestFullScanPipeline:
    @pytest.mark.asyncio
    async def test_full_scan_on_python_app(self, python_app, tmp_path):
        """Run the full orchestrator on python_app fixture with mocked LLM and sandbox."""
        config = ArgusConfig()
        config.scan.include = []
        config.reconnaissance.auto_exclude = False
        config.validation.enabled = True
        config.triage.chain_analysis = True
        config.resume.enabled = False
        config.resume.state_dir = str(tmp_path / "scan-state")

        llm = MockLLMClient()
        sandbox = MockSandboxManager()

        orchestrator = ScanOrchestrator(
            project_root=python_app,
            llm_client=llm,
            sandbox=sandbox,
            config=config,
        )
        report = await orchestrator.run()

        assert isinstance(report, Report)
        assert report.scan_progress.status in (
            ScanStatus.COMPLETED,
            ScanStatus.PARTIAL,
        )

    @pytest.mark.asyncio
    async def test_recon_phase_populates_targets(self, python_app, tmp_path):
        """Verify the recon phase finds targets."""
        config = ArgusConfig()
        config.scan.include = []
        config.reconnaissance.auto_exclude = False
        config.resume.enabled = False
        config.resume.state_dir = str(tmp_path / "scan-state")

        llm = MockLLMClient()
        sandbox = MockSandboxManager()

        orchestrator = ScanOrchestrator(
            project_root=python_app,
            llm_client=llm,
            sandbox=sandbox,
            config=config,
        )
        report = await orchestrator.run()
        # The python_app has vulnerable functions that should be scored above threshold
        assert report.scan_progress.targets_total > 0

    @pytest.mark.asyncio
    async def test_findings_in_report(self, python_app, tmp_path):
        """Verify findings are produced."""
        config = ArgusConfig()
        config.scan.include = []
        config.reconnaissance.auto_exclude = False
        config.validation.enabled = False  # skip validation for speed
        config.triage.chain_analysis = False
        config.resume.enabled = False
        config.resume.state_dir = str(tmp_path / "scan-state")

        llm = MockLLMClient()
        sandbox = MockSandboxManager()

        orchestrator = ScanOrchestrator(
            project_root=python_app,
            llm_client=llm,
            sandbox=sandbox,
            config=config,
        )
        report = await orchestrator.run()
        # MockLLM promotes hypotheses (confidence=0.8 > 0.7 threshold)
        assert len(report.findings) > 0

    @pytest.mark.asyncio
    async def test_llm_calls_made(self, python_app, tmp_path):
        """Verify the LLM was actually called."""
        config = ArgusConfig()
        config.scan.include = []
        config.reconnaissance.auto_exclude = False
        config.validation.enabled = False
        config.triage.chain_analysis = False
        config.resume.enabled = False
        config.resume.state_dir = str(tmp_path / "scan-state")

        llm = MockLLMClient()
        sandbox = MockSandboxManager()

        orchestrator = ScanOrchestrator(
            project_root=python_app,
            llm_client=llm,
            sandbox=sandbox,
            config=config,
        )
        await orchestrator.run()
        # Should have called hypothesize and triage
        call_types = {c[0] for c in llm.calls}
        assert "hypothesize" in call_types
