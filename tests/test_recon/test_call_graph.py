"""Tests for call graph construction."""
from pathlib import Path

import pytest

from argus.models.core import Function
from argus.recon.call_graph import CallGraph, build_call_graph
from argus.recon.extractor import extract_functions


class TestBuildCallGraph:
    def test_build_from_python_app(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        graph = build_call_graph(funcs)
        # get_user calls get_db (which is in the same file)
        get_user = next(f for f in funcs if f.name == "get_user")
        get_db = next(f for f in funcs if f.name == "get_db")
        callees = graph.calls.get(get_user.identifier, set())
        assert get_db.identifier in callees

    def test_name_index_populated(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        graph = build_call_graph(funcs)
        assert "get_db" in graph.name_index
        assert len(graph.name_index["get_db"]) >= 1

    def test_caller_relationship(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        graph = build_call_graph(funcs)
        get_db = next(f for f in funcs if f.name == "get_db")
        callers = graph.callers.get(get_db.identifier, set())
        # get_db should be called by get_user and delete_user
        caller_names = set()
        for caller_id in callers:
            for f in funcs:
                if f.identifier == caller_id:
                    caller_names.add(f.name)
        assert "get_user" in caller_names or "delete_user" in caller_names


class TestGetCallers:
    def test_direct_callers(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("c", "b")
        callers = graph.get_callers("b", max_hops=1)
        assert set(callers) == {"a", "c"}

    def test_transitive_callers(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("b", "c")
        callers = graph.get_callers("c", max_hops=2)
        assert "b" in callers
        assert "a" in callers

    def test_max_hops_respected(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("b", "c")
        graph.add_call("c", "d")
        callers = graph.get_callers("d", max_hops=1)
        assert "c" in callers
        assert "a" not in callers


class TestGetCallees:
    def test_direct_callees(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("a", "c")
        callees = graph.get_callees("a", max_hops=1)
        assert set(callees) == {"b", "c"}

    def test_transitive_callees(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("b", "c")
        callees = graph.get_callees("a", max_hops=2)
        assert "b" in callees
        assert "c" in callees


class TestHopsBetween:
    def test_same_function(self):
        graph = CallGraph()
        assert graph.hops_between("a", "a") == 0

    def test_direct_call(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        assert graph.hops_between("a", "b") == 1

    def test_two_hops(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("b", "c")
        assert graph.hops_between("a", "c") == 2

    def test_not_connected(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("c", "d")
        assert graph.hops_between("a", "d") is None

    def test_bidirectional(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        # hops_between checks both calls and callers
        assert graph.hops_between("b", "a") == 1

    def test_max_hops_exceeded(self):
        graph = CallGraph()
        graph.add_call("a", "b")
        graph.add_call("b", "c")
        graph.add_call("c", "d")
        graph.add_call("d", "e")
        assert graph.hops_between("a", "e", max_hops=2) is None
        assert graph.hops_between("a", "e", max_hops=4) == 4


class TestMultiFileCallGraph:
    def test_cross_file_resolution(self, python_app):
        """Test that functions from multiple files are linked."""
        funcs_app = extract_functions(python_app / "app.py")
        funcs_models = extract_functions(python_app / "models.py")
        all_funcs = funcs_app + funcs_models
        graph = build_call_graph(all_funcs)
        # Both files have functions, and graph should index them all
        all_names = set()
        for name_list in graph.name_index.values():
            all_names.update(name_list)
        assert len(all_names) >= 6  # at least 6 functions across both files
