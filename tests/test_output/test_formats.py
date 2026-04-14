"""Tests for output formatting."""
import json
from datetime import datetime, timezone

import pytest

from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Finding, Classification
from prowl.models.output import Report
from prowl.models.scan import ScanProgress, ScanStatus, BudgetState
from prowl.output.formatter import format_report
from prowl.output.text import render_text
from prowl.output.json_output import render_json
from prowl.output.sarif import render_sarif
from prowl.output.ai_output import render_ai


def _make_report(findings=None):
    progress = ScanProgress(
        scan_id="test-001",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        targets_total=5,
        targets_scanned=5,
        budget=BudgetState(tokens_used=10000),
        wall_time_seconds=2.5,
    )
    if findings is None:
        findings = [
            Finding(
                finding_id="prowl-injection-app.py-10",
                stable_id="prowl-injection-app.py::get_user",
                title="SQL Injection in get_user",
                description="f-string SQL allows injection",
                severity=Severity.HIGH,
                category=SignalCategory.INJECTION,
                classification=Classification.EXPLOITABLE,
                confidence=0.9,
                reasoning="Uses f-string in SQL query",
                attack_scenario="Send user_id=1 OR 1=1",
                file_path="/app.py",
                function_name="get_user",
                start_line=10,
                end_line=20,
            ),
            Finding(
                finding_id="prowl-auth-app.py-30",
                stable_id="prowl-auth-app.py::delete_user",
                title="Missing Auth on delete_user",
                description="No authorization check",
                severity=Severity.MEDIUM,
                category=SignalCategory.AUTH,
                classification=Classification.UNCERTAIN,
                confidence=0.6,
                file_path="/app.py",
                function_name="delete_user",
                start_line=30,
                end_line=40,
            ),
        ]
    return Report(scan_progress=progress, findings=findings)


class TestTextFormat:
    def test_contains_header(self):
        report = _make_report()
        text = render_text(report)
        assert "ARGUS SCAN REPORT" in text

    def test_contains_findings(self):
        report = _make_report()
        text = render_text(report)
        assert "SQL Injection in get_user" in text
        assert "Missing Auth on delete_user" in text

    def test_contains_severity(self):
        report = _make_report()
        text = render_text(report)
        assert "HIGH" in text
        assert "MEDIUM" in text

    def test_contains_status(self):
        report = _make_report()
        text = render_text(report)
        assert "completed" in text

    def test_empty_findings(self):
        report = _make_report(findings=[])
        text = render_text(report)
        assert "No findings" in text

    def test_format_dispatch(self):
        report = _make_report()
        text = format_report(report, "text")
        assert "ARGUS SCAN REPORT" in text


class TestJsonFormat:
    def test_valid_json(self):
        report = _make_report()
        output = render_json(report)
        data = json.loads(output)
        assert "scan_progress" in data
        assert "findings" in data

    def test_findings_count(self):
        report = _make_report()
        output = render_json(report)
        data = json.loads(output)
        assert len(data["findings"]) == 2

    def test_finding_fields(self):
        report = _make_report()
        output = render_json(report)
        data = json.loads(output)
        f = data["findings"][0]
        assert "finding_id" in f
        assert "severity" in f
        assert "category" in f
        assert "title" in f

    def test_format_dispatch(self):
        report = _make_report()
        output = format_report(report, "json")
        data = json.loads(output)
        assert "findings" in data


class TestSarifFormat:
    def test_valid_sarif_structure(self):
        report = _make_report()
        output = render_sarif(report)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_tool_info(self):
        report = _make_report()
        output = render_sarif(report)
        data = json.loads(output)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Prowl"
        assert "rules" in tool

    def test_sarif_results_count(self):
        report = _make_report()
        output = render_sarif(report)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_fields(self):
        report = _make_report()
        output = render_sarif(report)
        data = json.loads(output)
        result = data["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result
        assert len(result["locations"]) > 0
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc

    def test_sarif_level_mapping(self):
        report = _make_report()
        output = render_sarif(report)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        # HIGH severity -> error level
        high_result = next(r for r in results if r["properties"]["prowl-finding-id"] == "prowl-injection-app.py-10")
        assert high_result["level"] == "error"
        # MEDIUM severity -> warning level
        medium_result = next(r for r in results if r["properties"]["prowl-finding-id"] == "prowl-auth-app.py-30")
        assert medium_result["level"] == "warning"

    def test_sarif_empty_findings(self):
        report = _make_report(findings=[])
        output = render_sarif(report)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0

    def test_format_dispatch(self):
        report = _make_report()
        output = format_report(report, "sarif")
        data = json.loads(output)
        assert data["version"] == "2.1.0"


class TestAIFormat:
    def test_valid_json(self):
        report = _make_report()
        output = render_ai(report)
        data = json.loads(output)
        assert data["format"] == "ai"
        assert "findings" in data
        assert "scan_status" in data

    def test_ai_finding_fields(self):
        report = _make_report()
        output = render_ai(report)
        data = json.loads(output)
        f = data["findings"][0]
        assert "id" in f
        assert "severity" in f
        assert "category" in f
        assert "title" in f
        assert "narrative" in f
        assert "affected_function" in f
        assert "remediation" in f

    def test_ai_narrative_contains_function_name(self):
        report = _make_report()
        output = render_ai(report)
        data = json.loads(output)
        f = data["findings"][0]
        assert "get_user" in f["narrative"]

    def test_ai_remediation_has_category(self):
        report = _make_report()
        output = render_ai(report)
        data = json.loads(output)
        f = data["findings"][0]
        assert "category" in f["remediation"]

    def test_format_dispatch(self):
        report = _make_report()
        output = format_report(report, "ai")
        data = json.loads(output)
        assert data["format"] == "ai"
