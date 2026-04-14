"""Tests for triage classification."""
import pytest

from prowl.models.core import Severity, SignalCategory
from prowl.models.finding import Finding, Classification
from prowl.triage.classifier import should_validate, filter_for_validation


def _make_finding(classification, severity, **kwargs):
    return Finding(
        finding_id="prowl-test-file-1",
        stable_id="prowl-test-file::func",
        title="Test Finding",
        description="Test",
        severity=severity,
        category=SignalCategory.INJECTION,
        classification=classification,
        confidence=0.8,
        **kwargs,
    )


class TestShouldValidateExploitable:
    def test_exploitable_high_severity(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.HIGH)
        assert should_validate(f, severity_gate="high")

    def test_exploitable_critical_severity(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.CRITICAL)
        assert should_validate(f, severity_gate="high")

    def test_uncertain_high_severity(self):
        f = _make_finding(Classification.UNCERTAIN, Severity.HIGH)
        assert should_validate(f, severity_gate="high")

    def test_uncertain_medium_with_medium_gate(self):
        f = _make_finding(Classification.UNCERTAIN, Severity.MEDIUM)
        assert should_validate(f, severity_gate="medium")


class TestShouldNotValidateFP:
    def test_false_positive_not_validated(self):
        f = _make_finding(Classification.FALSE_POSITIVE, Severity.HIGH)
        assert not should_validate(f, severity_gate="high")

    def test_mitigated_not_validated(self):
        f = _make_finding(Classification.MITIGATED, Severity.HIGH)
        assert not should_validate(f, severity_gate="high")


class TestSeverityGate:
    def test_medium_below_high_gate(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.MEDIUM)
        assert not should_validate(f, severity_gate="high")

    def test_low_below_high_gate(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.LOW)
        assert not should_validate(f, severity_gate="high")

    def test_low_above_info_gate(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.LOW)
        assert should_validate(f, severity_gate="info")

    def test_info_below_low_gate(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.INFO)
        assert not should_validate(f, severity_gate="low")

    def test_critical_above_any_gate(self):
        f = _make_finding(Classification.EXPLOITABLE, Severity.CRITICAL)
        assert should_validate(f, severity_gate="low")


class TestFilterForValidation:
    def test_filters_correctly(self):
        findings = [
            _make_finding(Classification.EXPLOITABLE, Severity.HIGH),
            _make_finding(Classification.FALSE_POSITIVE, Severity.HIGH),
            _make_finding(Classification.UNCERTAIN, Severity.HIGH),
            _make_finding(Classification.MITIGATED, Severity.HIGH),
            _make_finding(Classification.EXPLOITABLE, Severity.LOW),
        ]
        result = filter_for_validation(findings, severity_gate="high")
        assert len(result) == 2  # exploitable high + uncertain high

    def test_empty_list(self):
        result = filter_for_validation([], severity_gate="high")
        assert result == []
