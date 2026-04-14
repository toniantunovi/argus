"""Call graph construction: intra-file, cross-file import tracing, heuristic matching."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from prowl.models.core import Function


class CallGraph:
    """Approximate call graph built from tree-sitter analysis."""

    def __init__(self) -> None:
        # Maps function identifier -> set of called function identifiers
        self.calls: dict[str, set[str]] = defaultdict(set)
        # Maps function identifier -> set of caller function identifiers
        self.callers: dict[str, set[str]] = defaultdict(set)
        # Maps function name -> list of function identifiers (for ambiguous resolution)
        self.name_index: dict[str, list[str]] = defaultdict(list)
        # Import map: file_path -> dict of imported_name -> source_module
        self.imports: dict[str, dict[str, str]] = defaultdict(dict)
        # Unresolved calls
        self.unresolved: dict[str, list[str]] = defaultdict(list)

    def add_function(self, func: Function) -> None:
        self.name_index[func.name].append(func.identifier)

    def add_call(self, caller_id: str, callee_id: str) -> None:
        self.calls[caller_id].add(callee_id)
        self.callers[callee_id].add(caller_id)

    def get_callers(self, func_id: str, max_hops: int = 2) -> list[str]:
        """Get callers up to max_hops away."""
        result: list[str] = []
        visited = {func_id}
        frontier = [func_id]
        for _ in range(max_hops):
            next_frontier: list[str] = []
            for fid in frontier:
                for caller in self.callers.get(fid, []):
                    if caller not in visited:
                        visited.add(caller)
                        result.append(caller)
                        next_frontier.append(caller)
            frontier = next_frontier
        return result

    def get_callees(self, func_id: str, max_hops: int = 2) -> list[str]:
        """Get callees up to max_hops away."""
        result: list[str] = []
        visited = {func_id}
        frontier = [func_id]
        for _ in range(max_hops):
            next_frontier: list[str] = []
            for fid in frontier:
                for callee in self.calls.get(fid, []):
                    if callee not in visited:
                        visited.add(callee)
                        result.append(callee)
                        next_frontier.append(callee)
            frontier = next_frontier
        return result

    def hops_between(self, func_a: str, func_b: str, max_hops: int = 3) -> int | None:
        """BFS to find minimum hops between two functions.

        Returns None if not connected within max_hops.
        """
        if func_a == func_b:
            return 0
        visited = {func_a}
        frontier = {func_a}
        for hop in range(1, max_hops + 1):
            next_frontier: set[str] = set()
            for fid in frontier:
                neighbors = self.calls.get(fid, set()) | self.callers.get(fid, set())
                for n in neighbors:
                    if n == func_b:
                        return hop
                    if n not in visited:
                        visited.add(n)
                        next_frontier.add(n)
            frontier = next_frontier
            if not frontier:
                break
        return None


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------

# Python: import X, from X import Y, from X import Y as Z
_PY_IMPORT_SIMPLE = re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE)
_PY_FROM_IMPORT = re.compile(
    r"^\s*from\s+([\w.]+)\s+import\s+(.+)", re.MULTILINE
)

# JS/TS: import { X } from 'Y', import X from 'Y', const X = require('Y')
_JS_IMPORT_NAMED = re.compile(
    r"""import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]""",
)
_JS_IMPORT_DEFAULT = re.compile(
    r"""import\s+(\w+)\s+from\s+['"]([^'"]+)['"]""",
)
_JS_REQUIRE = re.compile(
    r"""(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
)

# Java: import X.Y.Z
_JAVA_IMPORT = re.compile(r"^\s*import\s+([\w.]+)\s*;", re.MULTILINE)

# Go: import "X", import X "Y", import ( ... )
_GO_IMPORT_SINGLE = re.compile(r"""import\s+(?:(\w+)\s+)?["']([^"']+)["']""")
_GO_IMPORT_GROUP = re.compile(
    r"""import\s*\(\s*((?:(?:\w+\s+)?["'][^"']+["']\s*)+)\)""", re.DOTALL
)
_GO_IMPORT_LINE = re.compile(r"""(?:(\w+)\s+)?["']([^"']+)["']""")

# C/C++: #include "X", #include <X>
_C_INCLUDE = re.compile(r"""^\s*#\s*include\s+(?:["']([^"']+)["']|<([^>]+)>)""", re.MULTILINE)


def _extract_imports(file_path: Path, language: str) -> dict[str, str]:
    """Extract import statements from a file, returning {imported_name: source_module}.

    Reads the file if it exists; otherwise returns an empty dict.
    """
    try:
        content = file_path.read_text(errors="replace")
    except (OSError, IOError):
        return {}

    imports: dict[str, str] = {}

    if language == "python":
        for m in _PY_IMPORT_SIMPLE.finditer(content):
            module = m.group(1)
            # 'import os.path' => name 'os'
            top_name = module.split(".")[0]
            imports[top_name] = module

        for m in _PY_FROM_IMPORT.finditer(content):
            module = m.group(1)
            names_str = m.group(2)
            # Handle multiline with backslash continuation / parens (approximate)
            for part in names_str.split(","):
                part = part.strip().rstrip("\\").strip("()")
                if not part or part.startswith("#"):
                    continue
                # Handle 'Y as Z'
                as_match = re.match(r"(\w+)\s+as\s+(\w+)", part)
                if as_match:
                    imports[as_match.group(2)] = module
                else:
                    name = part.split()[0] if part.split() else part
                    name = name.strip()
                    if name.isidentifier():
                        imports[name] = module

    elif language in ("javascript", "typescript", "tsx"):
        for m in _JS_IMPORT_NAMED.finditer(content):
            names_str = m.group(1)
            source = m.group(2)
            for part in names_str.split(","):
                part = part.strip()
                # Handle 'X as Y'
                as_match = re.match(r"(\w+)\s+as\s+(\w+)", part)
                if as_match:
                    imports[as_match.group(2)] = source
                elif part and part.isidentifier():
                    imports[part] = source

        for m in _JS_IMPORT_DEFAULT.finditer(content):
            imports[m.group(1)] = m.group(2)

        for m in _JS_REQUIRE.finditer(content):
            source = m.group(3)
            if m.group(1):
                # destructured require: const { X, Y } = require('Z')
                for part in m.group(1).split(","):
                    part = part.strip()
                    if part and part.isidentifier():
                        imports[part] = source
            elif m.group(2):
                imports[m.group(2)] = source

    elif language == "java":
        for m in _JAVA_IMPORT.finditer(content):
            full_path = m.group(1)
            # 'import com.example.Foo' => name 'Foo'
            class_name = full_path.rsplit(".", 1)[-1]
            if class_name != "*":
                imports[class_name] = full_path

    elif language == "go":
        for m in _GO_IMPORT_SINGLE.finditer(content):
            alias = m.group(1)
            pkg = m.group(2)
            name = alias if alias else pkg.rsplit("/", 1)[-1]
            imports[name] = pkg

        for m in _GO_IMPORT_GROUP.finditer(content):
            block = m.group(1)
            for line_m in _GO_IMPORT_LINE.finditer(block):
                alias = line_m.group(1)
                pkg = line_m.group(2)
                name = alias if alias else pkg.rsplit("/", 1)[-1]
                imports[name] = pkg

    elif language in ("c", "cpp"):
        for m in _C_INCLUDE.finditer(content):
            header = m.group(1) or m.group(2)
            # Use filename without extension as the imported name
            stem = Path(header).stem
            imports[stem] = header

    return imports


# ---------------------------------------------------------------------------
# Call name extraction
# ---------------------------------------------------------------------------

# Matches function calls: name(, obj.name(, obj::name(, pkg.name(
_CALL_PATTERN = re.compile(
    r"""(?:(?:[\w.]+)\s*(?:::|\.|->)\s*)?(\w+)\s*\(""",
)

# Pattern to detect function definitions (to exclude them from call extraction)
_DEF_PATTERN = re.compile(
    r"""\b(?:def|func|fn|function)\s+(\w+)\s*\(""",
)

# Language keywords that look like calls but aren't
_KEYWORDS = frozenset({
    "if", "else", "elif", "for", "while", "switch", "case", "return",
    "break", "continue", "try", "catch", "except", "finally", "throw",
    "throws", "raise", "import", "from", "class", "struct", "enum",
    "interface", "def", "func", "fn", "function", "var", "let", "const",
    "new", "delete", "sizeof", "typeof", "instanceof", "assert",
    "yield", "await", "async", "with", "as", "pass", "lambda",
    "range", "print", "println", "printf", "fmt",  # common but uninteresting
})


def _extract_call_names(source: str, language: str) -> list[str]:
    """Extract function call names from source code.

    Returns a deduplicated list of function names that appear to be called.
    Excludes names that only appear as function definitions.
    """
    # Collect names that are being *defined*, not called
    defined_positions: set[int] = set()
    for m in _DEF_PATTERN.finditer(source):
        defined_positions.add(m.start(1))

    seen: set[str] = set()
    result: list[str] = []

    for m in _CALL_PATTERN.finditer(source):
        name = m.group(1)
        if not name or name in _KEYWORDS or name in seen:
            continue
        # Skip if this match position corresponds to a function definition
        if m.start(1) in defined_positions:
            continue
        seen.add(name)
        result.append(name)

    return result


# ---------------------------------------------------------------------------
# Call resolution
# ---------------------------------------------------------------------------

def _resolve_call(
    call_name: str,
    caller_func: Function,
    graph: CallGraph,
    func_map: dict[str, Function],
) -> str | None:
    """Try to resolve a call name to a function identifier.

    Resolution order:
    1. Same-file functions (strongest signal)
    2. Imported names via import map
    3. Name-based heuristic: exactly one match => use it
    """
    candidates = graph.name_index.get(call_name, [])
    if not candidates:
        return None

    caller_file = str(caller_func.file_path)

    # 1. Same-file match
    same_file = [c for c in candidates if c.startswith(caller_file + "::")]
    if len(same_file) == 1:
        return same_file[0]

    # 2. Import-based resolution
    file_imports = graph.imports.get(caller_file, {})
    if call_name in file_imports:
        # The call name was explicitly imported. Try to find a function whose
        # file path contains the module name.
        module = file_imports[call_name]
        module_parts = module.replace(".", "/").split("/")
        for c in candidates:
            func = func_map.get(c)
            if func is None:
                continue
            fpath = str(func.file_path)
            # Check if any part of the module path appears in the file path
            if any(part in fpath for part in module_parts if len(part) > 2):
                return c

    # 3. Global heuristic: exactly one candidate
    if len(candidates) == 1:
        return candidates[0]

    # Multiple candidates, ambiguous => unresolved
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_call_graph(functions: list[Function]) -> CallGraph:
    """Build call graph from a list of extracted functions."""
    graph = CallGraph()

    # Index all functions
    func_map: dict[str, Function] = {}
    for func in functions:
        graph.add_function(func)
        func_map[func.identifier] = func

    # Extract imports per file
    files_seen: set[str] = set()
    for func in functions:
        fpath = str(func.file_path)
        if fpath not in files_seen:
            files_seen.add(fpath)
            graph.imports[fpath] = _extract_imports(func.file_path, func.language)

    # For each function, find call sites in its source
    for func in functions:
        call_names = _extract_call_names(func.source, func.language)
        for call_name in call_names:
            resolved = _resolve_call(call_name, func, graph, func_map)
            if resolved:
                graph.add_call(func.identifier, resolved)
            else:
                graph.unresolved[func.identifier].append(call_name)

    return graph
