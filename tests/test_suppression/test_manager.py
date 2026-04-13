"""Tests for suppression manager."""
from pathlib import Path

import pytest

from argus.models.core import Severity, SignalCategory
from argus.models.finding import Finding, Classification
from argus.suppression.manager import SuppressionManager


def _make_finding(finding_id="argus-injection-app.py-10", stable_id="argus-injection-app.py::func",
                  function_name="func", file_path="/app.py", category=SignalCategory.INJECTION):
    return Finding(
        finding_id=finding_id,
        stable_id=stable_id,
        title="Test Finding",
        description="Test",
        severity=Severity.HIGH,
        category=category,
        classification=Classification.EXPLOITABLE,
        confidence=0.8,
        file_path=file_path,
        function_name=function_name,
        start_line=10,
        end_line=20,
    )


class TestSuppressAndCheck:
    def test_suppress_finding(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("argus-injection-app.py-10", reason="False positive")
        f = _make_finding()
        assert mgr.is_suppressed(f)

    def test_not_suppressed_by_default(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        f = _make_finding()
        assert not mgr.is_suppressed(f)

    def test_suppress_by_stable_id(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("argus-injection-app.py::func", reason="Known issue",
                      stable_id="argus-injection-app.py::func")
        f = _make_finding()
        assert mgr.is_suppressed(f)


class TestScopeFunction:
    def test_function_scope_matches_function_name(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("sup1", reason="Function-level suppression",
                      scope="function", function_name="func")
        f = _make_finding(finding_id="other-id", stable_id="other-stable")
        assert mgr.is_suppressed(f)

    def test_function_scope_with_file_path(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("sup1", reason="Function-level", scope="function",
                      function_name="func", file_path="/app.py")
        f = _make_finding(file_path="/app.py")
        assert mgr.is_suppressed(f)

    def test_function_scope_wrong_file(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("sup1", reason="Function-level", scope="function",
                      function_name="func", file_path="/other.py")
        f = _make_finding(file_path="/app.py")
        assert not mgr.is_suppressed(f)


class TestScopeProject:
    def test_project_scope_matches_category(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("sup1", reason="Project-wide", scope="project",
                      category="injection")
        f = _make_finding(finding_id="different", stable_id="different-stable",
                          category=SignalCategory.INJECTION)
        assert mgr.is_suppressed(f)

    def test_project_scope_wrong_category(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("sup1", reason="Project-wide", scope="project",
                      category="auth")
        f = _make_finding(category=SignalCategory.INJECTION)
        assert not mgr.is_suppressed(f)


class TestUnsuppress:
    def test_unsuppress_existing(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("argus-injection-app.py-10", reason="FP")
        result = mgr.unsuppress("argus-injection-app.py-10")
        assert result is True
        f = _make_finding()
        assert not mgr.is_suppressed(f)

    def test_unsuppress_nonexistent(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        result = mgr.unsuppress("nonexistent")
        assert result is False


class TestOrphanDetection:
    def test_detect_orphans(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("orphan-id", reason="Old suppression",
                      stable_id="orphan-stable")
        mgr.suppress("current-id", reason="Current",
                      stable_id="current-stable")

        current_findings = [
            _make_finding(finding_id="current-id", stable_id="current-stable")
        ]
        orphans = mgr.detect_orphans(current_findings)
        assert len(orphans) == 1
        assert orphans[0].finding_id == "orphan-id"

    def test_no_orphans_when_all_match(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("argus-injection-app.py-10", reason="Known")

        current_findings = [_make_finding()]
        orphans = mgr.detect_orphans(current_findings)
        assert len(orphans) == 0


class TestFilterFindings:
    def test_filter_removes_suppressed(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        mgr.suppress("argus-injection-app.py-10", reason="FP")

        findings = [
            _make_finding(),
            _make_finding(finding_id="argus-auth-app.py-20",
                          stable_id="argus-auth-app.py::other",
                          function_name="other",
                          category=SignalCategory.AUTH),
        ]
        filtered = mgr.filter_findings(findings)
        assert len(filtered) == 1
        assert filtered[0].finding_id == "argus-auth-app.py-20"

    def test_filter_empty_list(self, tmp_path):
        mgr = SuppressionManager(tmp_path)
        assert mgr.filter_findings([]) == []


class TestPersistence:
    def test_suppressions_persist(self, tmp_path):
        mgr1 = SuppressionManager(tmp_path)
        mgr1.suppress("persist-id", reason="Persist test")

        mgr2 = SuppressionManager(tmp_path)
        assert len(mgr2.suppressions) == 1
        assert mgr2.suppressions[0].finding_id == "persist-id"
