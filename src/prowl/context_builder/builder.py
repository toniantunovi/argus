"""Main context assembly orchestrator."""
from __future__ import annotations

import re
from pathlib import Path

from prowl.context_builder.framework import detect_framework
from prowl.context_builder.sanitizers import find_sanitizers_in_path
from prowl.models.context import ExploitContext, FindingContext, FunctionContext
from prowl.models.core import Function, SignalCategory, Target
from prowl.recon.call_graph import CallGraph
from prowl.rubrics.loader import load_rubric

# Build system detection: (filename, hint) pairs checked in priority order.
_BUILD_SYSTEM_MARKERS: list[tuple[str, str]] = [
    ("CMakeLists.txt", "cmake"),
    ("configure.ac", "autotools"),
    ("configure", "autotools"),
    ("meson.build", "meson"),
    ("Cargo.toml", "cargo"),
    ("go.mod", "go"),
    ("package.json", "npm"),
    ("pyproject.toml", "pip"),
    ("setup.py", "pip"),
    ("requirements.txt", "pip"),
    ("pom.xml", "maven"),
    ("build.gradle", "gradle"),
    ("Makefile", "make"),
]


def detect_build_system(project_root: str) -> str | None:
    """Detect build system from files present in the project root."""
    root = Path(project_root)
    if not root.is_dir():
        return None
    for filename, hint in _BUILD_SYSTEM_MARKERS:
        if (root / filename).exists():
            return hint
    return None


# Server indicator patterns per language group.
_C_SERVER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\blisten\s*\("), "POSIX listen()"),
    (re.compile(r"\baccept\s*\("), "POSIX accept()"),
    (re.compile(r"\bbind\s*\([^)]*INADDR"), "socket bind to address"),
    (re.compile(r"\bevent_base_dispatch\b"), "libevent event loop"),
    (re.compile(r"\bev_run\b"), "libev event loop"),
    (re.compile(r"\bepoll_create\b"), "epoll event loop"),
    (re.compile(r"\buv_listen\b"), "libuv server"),
    (re.compile(r"\baeMain\b"), "ae event loop (Redis-style)"),
    (re.compile(r"\baeCreateEventLoop\b"), "ae event loop creation"),
    (re.compile(r"\bselect\s*\([^)]*nfds"), "select loop"),
    (re.compile(r"\bpoll\s*\([^)]*pollfd"), "poll loop"),
    (re.compile(r"\bMHD_start_daemon\b"), "libmicrohttpd server"),
]

_GO_SERVER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"http\.ListenAndServe"), "HTTP server"),
    (re.compile(r"\.ListenAndServeTLS\b"), "HTTPS server"),
    (re.compile(r"net\.Listen\b"), "TCP/UDP listener"),
    (re.compile(r"grpc\.NewServer\b"), "gRPC server"),
    (re.compile(r"gin\.Default\b"), "Gin HTTP framework"),
    (re.compile(r"echo\.New\b"), "Echo HTTP framework"),
    (re.compile(r"fiber\.New\b"), "Fiber HTTP framework"),
    (re.compile(r"mux\.NewRouter\b"), "Gorilla Mux router"),
    (re.compile(r"chi\.NewRouter\b"), "Chi router"),
]

_RUST_SERVER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"TcpListener::bind\b"), "TCP listener"),
    (re.compile(r"HttpServer::new\b"), "actix-web server"),
    (re.compile(r"axum::Router\b"), "Axum server"),
    (re.compile(r"warp::serve\b"), "Warp server"),
    (re.compile(r"rocket::build\b"), "Rocket server"),
    (re.compile(r"hyper::Server\b"), "Hyper server"),
    (re.compile(r"tonic::transport::Server\b"), "tonic gRPC server"),
]

_SERVER_PATTERNS_BY_LANGUAGE: dict[str, list[tuple[re.Pattern, str]]] = {
    "c": _C_SERVER_PATTERNS,
    "cpp": _C_SERVER_PATTERNS,
    "go": _GO_SERVER_PATTERNS,
    "rust": _RUST_SERVER_PATTERNS,
}


def detect_server_indicators(
    language: str, functions: dict[str, Function],
) -> list[str]:
    """Detect if the project runs as a network server/daemon.

    Scans all functions in the matching language for socket, event loop,
    and HTTP server patterns.  Returns a list of human-readable indicator
    strings (empty if nothing found).
    """
    patterns = _SERVER_PATTERNS_BY_LANGUAGE.get(language, [])
    if not patterns:
        return []

    indicators: list[str] = []
    seen: set[str] = set()
    for func in functions.values():
        if func.language != language:
            continue
        for pattern, description in patterns:
            if description not in seen and pattern.search(func.source):
                indicators.append(description)
                seen.add(description)
    return indicators


class ContextBuilder:
    def __init__(self, functions: dict[str, Function], call_graph: CallGraph, project_root_str: str = ""):
        self.functions = functions  # identifier -> Function
        self.call_graph = call_graph
        self.project_root = project_root_str

    def build_hypothesis_context(self, target: Target) -> FunctionContext:
        """Build Layer 1 context for hypothesis generation."""
        func = target.function
        callers = self._get_caller_sources(func, max_hops=2)
        callees = self._get_callee_sources(func)
        categories = list({s.category for s in func.signals})
        rubric = load_rubric("detection", categories, target.score.rubric_tier)
        framework = detect_framework(func, self.functions)
        return FunctionContext(
            target_source=func.source,
            target_name=func.name,
            target_file=str(func.file_path),
            target_lines=(func.start_line, func.end_line),
            language=func.language,
            callers=callers,
            callees=callees,
            framework_context=framework,
            detection_rubric=rubric,
            risk_categories=categories,
            rubric_tier=target.score.rubric_tier,
        )

    def build_finding_context(self, target: Target, hypothesis_title: str, hypothesis_desc: str, hypothesis_category: SignalCategory) -> FindingContext:
        """Build Layer 2 context for triage."""
        func = target.function
        # Get call chain from entry point to sink
        entry_source = self._find_entry_point_source(func)
        call_chain = self._get_call_chain(func)
        sanitizers = find_sanitizers_in_path(func, call_chain, self.functions)
        rubric = load_rubric("triage", [hypothesis_category], target.score.rubric_tier)
        framework = detect_framework(func, self.functions)
        return FindingContext(
            target_source=func.source,
            target_name=func.name,
            target_file=str(func.file_path),
            target_lines=(func.start_line, func.end_line),
            language=func.language,
            sink_code=func.source,
            source_code=entry_source or "",
            call_chain=call_chain,
            framework=framework,
            sanitizers_in_path=sanitizers,
            evaluation_rubric=rubric,
            hypothesis_title=hypothesis_title,
            hypothesis_description=hypothesis_desc,
            hypothesis_category=hypothesis_category,
        )

    def build_exploit_context(self, target: Target, finding_category: SignalCategory, finding_severity: str, iteration_history: list[str] | None = None) -> ExploitContext:
        """Build Layer 3 context for PoC generation."""
        func = target.function
        call_chain = self._get_call_chain(func)
        entry_source = self._find_entry_point_source(func)
        sanitizers = find_sanitizers_in_path(func, call_chain, self.functions)
        rubric = load_rubric("exploit", [finding_category], target.score.rubric_tier)
        framework = detect_framework(func, self.functions)
        build_hint = detect_build_system(self.project_root) if self.project_root else None
        server_indicators = detect_server_indicators(func.language, self.functions)
        return ExploitContext(
            target_source=func.source,
            target_name=func.name,
            target_file=str(func.file_path),
            target_lines=(func.start_line, func.end_line),
            language=func.language,
            sink_code=func.source,
            source_code=entry_source or "",
            call_chain=call_chain,
            framework=framework,
            sanitizers_in_path=sanitizers,
            exploit_rubric=rubric,
            iteration_history=iteration_history or [],
            finding_severity=finding_severity,
            finding_category=finding_category,
            build_system_hint=build_hint,
            server_indicators=server_indicators,
        )

    def _get_caller_sources(self, func: Function, max_hops: int = 2) -> list[str]:
        caller_ids = self.call_graph.get_callers(func.identifier, max_hops=max_hops)
        return [self.functions[cid].source for cid in caller_ids if cid in self.functions]

    def _get_callee_sources(self, func: Function) -> list[str]:
        callee_ids = self.call_graph.get_callees(func.identifier, max_hops=1)
        return [self.functions[cid].source for cid in callee_ids if cid in self.functions]

    def _find_entry_point_source(self, func: Function) -> str | None:
        """Walk callers to find the nearest entry point."""
        visited = {func.identifier}
        frontier = [func.identifier]
        for _ in range(5):  # max 5 hops
            next_frontier = []
            for fid in frontier:
                for caller_id in self.call_graph.callers.get(fid, []):
                    if caller_id in visited:
                        continue
                    visited.add(caller_id)
                    caller = self.functions.get(caller_id)
                    if caller and caller.is_entry_point:
                        return caller.source
                    next_frontier.append(caller_id)
            frontier = next_frontier
        return None

    def _get_call_chain(self, func: Function) -> list[str]:
        """Get the call chain from nearest entry point to func as source strings."""
        # BFS from func toward callers to find entry point path
        chain: list[str] = []
        visited = {func.identifier}
        frontier = [(func.identifier, [func.identifier])]
        while frontier:
            current_id, path = frontier.pop(0)
            for caller_id in self.call_graph.callers.get(current_id, []):
                if caller_id in visited:
                    continue
                visited.add(caller_id)
                new_path = [caller_id] + path
                caller = self.functions.get(caller_id)
                if caller and caller.is_entry_point:
                    return [self.functions[p].source for p in new_path if p in self.functions]
                frontier.append((caller_id, new_path))
        # No entry point found, return immediate callers
        caller_ids = self.call_graph.get_callers(func.identifier, max_hops=2)
        return [self.functions[cid].source for cid in caller_ids if cid in self.functions]
