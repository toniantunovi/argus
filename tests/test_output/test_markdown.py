"""Tests for markdown output format."""
from datetime import datetime, timezone

import pytest

from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Finding, Classification
from prowl.models.output import Report
from prowl.models.scan import ScanProgress, ScanStatus, BudgetState
from prowl.output.formatter import format_report
from prowl.output.markdown import render_markdown


def _make_report(findings=None):
    progress = ScanProgress(
        scan_id="test-001",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        targets_total=5,
        targets_scanned=5,
        budget=BudgetState(tokens_used=10000),
        wall_time_seconds=2.5,
    )
    if findings is None:
        findings = [_sqli_finding(), _memory_finding_validated()]
    return Report(scan_progress=progress, findings=findings)


def _sqli_finding():
    return Finding(
        finding_id="prowl-injection-app.py-10",
        stable_id="prowl-injection-app.py::get_user",
        title="SQL Injection in get_user",
        description="f-string SQL allows injection via user_id parameter.",
        severity=Severity.HIGH,
        category=SignalCategory.INJECTION,
        classification=Classification.EXPLOITABLE,
        confidence=0.9,
        reasoning="Uses f-string in SQL query with unsanitized input",
        attack_scenario="Send user_id=1 OR 1=1 to bypass authentication",
        file_path="/app.py",
        function_name="get_user",
        start_line=10,
        end_line=20,
        validation_attempted=True,
        poc_validated=True,
        validation_method="marker",
        iterations_used=2,
        poc_code='import requests\n\nr = requests.get("http://localhost:5000/user?id=1 OR 1=1")\nprint(r.json())\nprint("ARGUS_POC_CONFIRMED")',
        validation_stdout='{"users": [...]}\nARGUS_POC_CONFIRMED',
    )


def _memory_finding_validated():
    return Finding(
        finding_id="prowl-memory-buffer.c-42",
        stable_id="prowl-memory-buffer.c::parse_input",
        title="Heap Buffer Overflow in parse_input",
        description="memcpy with unchecked length causes heap overflow.",
        severity=Severity.CRITICAL,
        category=SignalCategory.MEMORY,
        classification=Classification.EXPLOITABLE,
        confidence=0.95,
        reasoning="memcpy uses user-controlled size without bounds check",
        attack_scenario="Supply input longer than 256 bytes to trigger overflow",
        file_path="/src/buffer.c",
        function_name="parse_input",
        start_line=42,
        end_line=60,
        validation_attempted=True,
        poc_validated=True,
        validation_method="asan",
        iterations_used=3,
        poc_code='#include <string.h>\n#include <stdlib.h>\n#include "buffer.h"\n\nint main() {\n    char payload[512];\n    memset(payload, \'A\', sizeof(payload));\n    parse_input(payload, sizeof(payload));\n    return 0;\n}',
        validation_stderr="==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000ff",
        sanitizer_output={
            "sanitizer": "AddressSanitizer",
            "type": "heap-buffer-overflow",
            "details": "READ of size 512 at 0x6020000000ff thread T0",
        },
        patch_code='void parse_input(const char *input, size_t len) {\n    if (len > MAX_INPUT_SIZE) len = MAX_INPUT_SIZE;\n    memcpy(buf, input, len);\n}',
    )


def _unvalidated_finding():
    return Finding(
        finding_id="prowl-auth-routes.py-100",
        stable_id="prowl-auth-routes.py::delete_user",
        title="Missing Auth on delete_user",
        description="No authorization check on destructive endpoint.",
        severity=Severity.MEDIUM,
        category=SignalCategory.AUTH,
        classification=Classification.UNCERTAIN,
        confidence=0.6,
        file_path="/routes.py",
        function_name="delete_user",
        start_line=100,
        end_line=115,
    )


class TestMarkdownHeader:
    def test_contains_title(self):
        md = render_markdown(_make_report())
        assert "# Prowl Scan Report" in md

    def test_contains_status(self):
        md = render_markdown(_make_report())
        assert "`completed`" in md

    def test_contains_targets(self):
        md = render_markdown(_make_report())
        assert "5 / 5 scanned" in md

    def test_contains_duration(self):
        md = render_markdown(_make_report())
        assert "2.5s" in md

    def test_contains_tokens(self):
        md = render_markdown(_make_report())
        assert "10,000" in md

    def test_contains_validation_counts(self):
        md = render_markdown(_make_report())
        assert "| **Validation attempted** | 2 |" in md
        assert "| **PoC validated** | 2 |" in md


class TestMarkdownSummary:
    def test_severity_counts(self):
        md = render_markdown(_make_report())
        assert "**CRITICAL**" in md
        assert "**HIGH**" in md

    def test_empty_findings(self):
        md = render_markdown(_make_report(findings=[]))
        assert "No findings" in md


class TestMarkdownFindings:
    def test_finding_title(self):
        md = render_markdown(_make_report())
        assert "SQL Injection in get_user" in md
        assert "Heap Buffer Overflow in parse_input" in md

    def test_finding_metadata(self):
        md = render_markdown(_make_report())
        assert "`prowl-injection-app.py-10`" in md
        assert "injection" in md
        assert "90%" in md

    def test_description(self):
        md = render_markdown(_make_report())
        assert "f-string SQL allows injection" in md

    def test_attack_scenario(self):
        md = render_markdown(_make_report())
        assert "#### Attack Scenario" in md
        assert "1 OR 1=1" in md

    def test_reasoning(self):
        md = render_markdown(_make_report())
        assert "#### Analysis" in md


class TestMarkdownPoC:
    def test_poc_code_block_present(self):
        md = render_markdown(_make_report())
        assert "#### Proof of Concept" in md
        assert "```python" in md
        assert 'requests.get("http://localhost:5000/user?id=1 OR 1=1")' in md

    def test_c_poc_code_block(self):
        md = render_markdown(_make_report())
        assert "```c" in md
        assert "parse_input(payload, sizeof(payload))" in md

    def test_reproduction_instructions_memory(self):
        md = render_markdown(_make_report())
        assert "gcc -fsanitize=address" in md
        assert "ASAN violation" in md

    def test_reproduction_instructions_injection(self):
        md = render_markdown(_make_report())
        assert "ARGUS_POC_CONFIRMED" in md

    def test_execution_output(self):
        md = render_markdown(_make_report())
        assert "#### Execution Output" in md
        assert "ARGUS_POC_CONFIRMED" in md

    def test_sanitizer_output(self):
        md = render_markdown(_make_report())
        assert "#### Sanitizer Output" in md
        assert "AddressSanitizer" in md
        assert "heap-buffer-overflow" in md

    def test_patch_code(self):
        md = render_markdown(_make_report())
        assert "#### Suggested Patch" in md
        assert "MAX_INPUT_SIZE" in md

    def test_no_poc_for_unvalidated(self):
        report = _make_report(findings=[_unvalidated_finding()])
        md = render_markdown(report)
        assert "#### Proof of Concept" not in md
        assert "#### Sanitizer Output" not in md

    def test_validation_status_shown(self):
        md = render_markdown(_make_report())
        assert "VALIDATED" in md
        assert "marker" in md
        assert "asan" in md

    def test_failed_poc_code_still_in_report(self):
        """PoC code from a failed validation attempt must appear in the report."""
        f = _unvalidated_finding()
        f.validation_attempted = True
        f.validation_method = "failed"
        f.poc_code = 'import requests\nr = requests.get("http://localhost/admin")\nprint(r.status_code)'
        f.validation_stderr = "Connection refused"
        report = _make_report(findings=[f])
        md = render_markdown(report)
        assert "#### Proof of Concept (unconfirmed)" in md
        assert "requests.get" in md
        assert "#### Execution Output (stderr)" in md
        assert "Connection refused" in md

    def test_partial_poc_code_in_report(self):
        """PoC code from a partial validation must appear with partial label."""
        f = _unvalidated_finding()
        f.validation_attempted = True
        f.validation_method = "partial"
        f.poc_code = '#include <stdio.h>\nint main() { return 0; }'
        f.validation_stdout = "Segfault observed but no ASAN marker"
        report = _make_report(findings=[f])
        md = render_markdown(report)
        assert "#### Proof of Concept (partial" in md
        assert "#include <stdio.h>" in md
        assert "#### Execution Output" in md
        assert "Segfault observed" in md

    def test_execution_output_shown_for_confirmed(self):
        """Both stdout and stderr are shown for confirmed PoCs."""
        md = render_markdown(_make_report())
        assert "#### Execution Output" in md
        assert "ARGUS_POC_CONFIRMED" in md


class TestMarkdownChains:
    def test_chains_section(self):
        report = _make_report()
        report.chains = [
            {
                "chain_id": "chain-auth-sqli-001",
                "chain_type": "auth_bypass_to_data_access",
                "combined_severity": "critical",
                "description": "Auth bypass enables SQL injection on admin endpoint.",
                "finding_ids": ["prowl-auth-app.py-30", "prowl-injection-app.py-10"],
            }
        ]
        md = render_markdown(report)
        assert "## Attack Chains" in md
        assert "`chain-auth-sqli-001`" in md
        assert "auth_bypass_to_data_access" in md

    def test_no_chains_section_when_empty(self):
        md = render_markdown(_make_report())
        assert "## Attack Chains" not in md


class TestMarkdownFormatDispatch:
    def test_dispatch(self):
        report = _make_report()
        md = format_report(report, "markdown")
        assert "# Prowl Scan Report" in md

    def test_is_valid_markdown(self):
        """Basic structural check: headers, code fences balance."""
        report = _make_report()
        md = render_markdown(report)
        assert md.startswith("# ")
        # Code fences should be balanced
        assert md.count("```") % 2 == 0


class TestMarkdownFailedValidation:
    def test_failed_validation_shown_in_finding(self):
        f = _unvalidated_finding()
        f.validation_attempted = True
        f.validation_method = "failed"
        report = _make_report(findings=[f])
        md = render_markdown(report)
        assert "| **PoC status** | FAILED |" in md

    def test_skipped_validation_shown_in_finding(self):
        f = _unvalidated_finding()
        f.validation_attempted = True
        f.validation_method = "skipped"
        report = _make_report(findings=[f])
        md = render_markdown(report)
        assert "| **PoC status** | SKIPPED |" in md

    def test_failed_count_in_header(self):
        f = _unvalidated_finding()
        f.validation_attempted = True
        f.validation_method = "failed"
        report = _make_report(findings=[f])
        md = render_markdown(report)
        assert "| **Validation attempted** | 1 |" in md
        assert "| **Validation failed** | 1 |" in md

    def test_no_validation_section_when_not_attempted(self):
        report = _make_report(findings=[_unvalidated_finding()])
        md = render_markdown(report)
        assert "Validation attempted" not in md
        assert "PoC validated" not in md
        assert "FAILED" not in md


class TestMarkdownSorting:
    def test_findings_sorted_by_severity(self):
        """Critical findings appear before high, which appear before medium."""
        findings = [_unvalidated_finding(), _sqli_finding(), _memory_finding_validated()]
        report = _make_report(findings=findings)
        md = render_markdown(report)
        crit_pos = md.index("Heap Buffer Overflow")
        high_pos = md.index("SQL Injection")
        med_pos = md.index("Missing Auth")
        assert crit_pos < high_pos < med_pos
