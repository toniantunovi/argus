"""End-to-end recon integration test (no LLM needed)."""
from pathlib import Path

import pytest

from argus.models.core import Function, Target, ProjectType, SignalCategory
from argus.recon.call_graph import build_call_graph
from argus.recon.extractor import extract_functions
from argus.recon.signals import detect_signals
from argus.recon.scorer import score_functions
from argus.recon.prioritizer import prioritize_targets


class TestFullReconOnPythonApp:
    def test_extract_and_detect_signals(self, python_app):
        """Extract functions and detect signals across the python_app."""
        funcs_app = extract_functions(python_app / "app.py")
        funcs_models = extract_functions(python_app / "models.py")
        all_funcs = funcs_app + funcs_models

        # Should have functions from both files
        assert len(all_funcs) >= 8

        # Detect signals on all functions
        for f in all_funcs:
            f.signals = detect_signals(f)

        # Verify some functions have signals
        get_user = next(f for f in all_funcs if f.name == "get_user")
        assert len(get_user.signals) > 0
        categories = {s.category for s in get_user.signals}
        assert SignalCategory.DATA_ACCESS in categories

        run_command = next(f for f in all_funcs if f.name == "run_command")
        assert len(run_command.signals) > 0
        run_categories = {s.category for s in run_command.signals}
        assert SignalCategory.INJECTION in run_categories

    def test_score_and_prioritize(self, python_app):
        """Score all functions and verify prioritization."""
        funcs_app = extract_functions(python_app / "app.py")
        funcs_models = extract_functions(python_app / "models.py")
        all_funcs = funcs_app + funcs_models

        for f in all_funcs:
            f.signals = detect_signals(f)

        graph = build_call_graph(all_funcs)

        # Populate callers/callees
        for f in all_funcs:
            f.callers = list(graph.callers.get(f.identifier, set()))
            f.callees = list(graph.calls.get(f.identifier, set()))

        scores = score_functions(all_funcs, ProjectType.APPLICATION)
        targets = prioritize_targets(all_funcs, scores, graph)

        # Should have targets above threshold
        assert len(targets) > 0
        # Targets should be sorted by priority
        assert targets[0].priority_rank == 1
        # All targets should have score >= 1.0
        for t in targets:
            assert t.score.total >= 1.0

    def test_call_graph_connectivity(self, python_app):
        """Verify call graph connects related functions."""
        funcs = extract_functions(python_app / "app.py")
        graph = build_call_graph(funcs)

        get_db = next(f for f in funcs if f.name == "get_db")
        get_user = next(f for f in funcs if f.name == "get_user")

        # get_user should call get_db
        callees = graph.calls.get(get_user.identifier, set())
        assert get_db.identifier in callees

        # get_db should be called by get_user
        callers = graph.callers.get(get_db.identifier, set())
        assert get_user.identifier in callers

    def test_vulnerable_functions_prioritized(self, python_app):
        """Verify that obviously vulnerable functions appear in targets."""
        funcs_app = extract_functions(python_app / "app.py")
        funcs_models = extract_functions(python_app / "models.py")
        all_funcs = funcs_app + funcs_models

        for f in all_funcs:
            f.signals = detect_signals(f)

        graph = build_call_graph(all_funcs)
        for f in all_funcs:
            f.callers = list(graph.callers.get(f.identifier, set()))
            f.callees = list(graph.calls.get(f.identifier, set()))

        scores = score_functions(all_funcs, ProjectType.APPLICATION)
        targets = prioritize_targets(all_funcs, scores, graph)
        target_names = {t.function.name for t in targets}

        # These functions have clear vulnerabilities and should be targets
        # (run_command has injection, get_user has SQL injection/data access)
        assert "run_command" in target_names or "get_user" in target_names

    def test_full_pipeline_produces_targets_with_all_fields(self, python_app):
        """Verify targets have all required fields populated."""
        funcs = extract_functions(python_app / "app.py")
        for f in funcs:
            f.signals = detect_signals(f)

        graph = build_call_graph(funcs)
        for f in funcs:
            f.callers = list(graph.callers.get(f.identifier, set()))
            f.callees = list(graph.calls.get(f.identifier, set()))

        scores = score_functions(funcs, ProjectType.APPLICATION)
        targets = prioritize_targets(funcs, scores, graph)

        for target in targets:
            assert target.function.name != ""
            assert target.function.source != ""
            assert target.function.language == "python"
            assert target.score.total >= 1.0
            assert target.priority_rank > 0
            assert target.function.file_path.exists()
