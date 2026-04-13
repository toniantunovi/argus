"""AST-level source-to-sink taint tracking."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from argus.models.core import Function, SignalCategory

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    variable: str
    origin: str  # e.g., "request.json", "sys.argv", "stdin"
    line: int


@dataclass
class TaintSink:
    function_call: str  # e.g., "cursor.execute", "os.system"
    category: SignalCategory
    line: int
    tainted_arg: str | None = None


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    path: list[str] = field(default_factory=list)  # intermediate variable names
    sanitizers: list[str] = field(default_factory=list)
    through_unresolved: bool = False


# ---------------------------------------------------------------------------
# Taint source patterns (language-aware)
# ---------------------------------------------------------------------------

# Each entry: (regex, origin_label, language_constraint_or_None)
_SOURCE_PATTERNS: list[tuple[re.Pattern[str], str, frozenset[str] | None]] = [
    # Python
    (re.compile(r"\brequest\s*\.\s*json\b"), "request.json", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*form\b"), "request.form", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*data\b"), "request.data", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*args\b"), "request.args", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*values\b"), "request.values", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*files\b"), "request.files", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*headers\b"), "request.headers", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*cookies\b"), "request.cookies", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*GET\b"), "request.GET", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*POST\b"), "request.POST", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*body\b"), "request.body", frozenset({"python"})),
    (re.compile(r"\brequest\s*\.\s*query_params\b"), "request.query_params", frozenset({"python"})),
    (re.compile(r"\bsys\s*\.\s*argv\b"), "sys.argv", frozenset({"python"})),
    (re.compile(r"\binput\s*\("), "input()", frozenset({"python"})),
    (re.compile(r"\bsys\s*\.\s*stdin\b"), "sys.stdin", frozenset({"python"})),
    (re.compile(r"\bos\s*\.\s*environ\b"), "os.environ", frozenset({"python"})),
    (re.compile(r"\bjson\s*\.\s*loads?\s*\("), "json.load", frozenset({"python"})),
    (re.compile(r"\bpickle\s*\.\s*loads?\s*\("), "pickle.load", frozenset({"python"})),
    (re.compile(r"\byaml\s*\.\s*(load|unsafe_load)\s*\("), "yaml.load", frozenset({"python"})),

    # JS/TS
    (re.compile(r"\breq\s*\.\s*body\b"), "req.body", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\breq\s*\.\s*params\b"), "req.params", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\breq\s*\.\s*query\b"), "req.query", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\breq\s*\.\s*headers\b"), "req.headers", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\breq\s*\.\s*cookies\b"), "req.cookies", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\bJSON\s*\.\s*parse\s*\("), "JSON.parse", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\bprocess\s*\.\s*argv\b"), "process.argv", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\bprocess\s*\.\s*env\b"), "process.env", frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\bprocess\s*\.\s*stdin\b"), "process.stdin", frozenset({"javascript", "typescript", "tsx"})),

    # Java
    (re.compile(r"\bgetParameter\s*\("), "getParameter()", frozenset({"java"})),
    (re.compile(r"\bgetHeader\s*\("), "getHeader()", frozenset({"java"})),
    (re.compile(r"\bgetInputStream\s*\("), "getInputStream()", frozenset({"java"})),
    (re.compile(r"\bgetReader\s*\("), "getReader()", frozenset({"java"})),
    (re.compile(r"@RequestBody\b"), "@RequestBody", frozenset({"java"})),
    (re.compile(r"@RequestParam\b"), "@RequestParam", frozenset({"java"})),
    (re.compile(r"@PathVariable\b"), "@PathVariable", frozenset({"java"})),

    # Go
    (re.compile(r"\br\.Body\b"), "r.Body", frozenset({"go"})),
    (re.compile(r"\br\s*\.\s*FormValue\s*\("), "r.FormValue()", frozenset({"go"})),
    (re.compile(r"\bjson\s*\.\s*NewDecoder\b"), "json.NewDecoder", frozenset({"go"})),
    (re.compile(r"\bjson\s*\.\s*Unmarshal\b"), "json.Unmarshal", frozenset({"go"})),
    (re.compile(r"\bos\s*\.\s*Args\b"), "os.Args", frozenset({"go"})),

    # C/C++
    (re.compile(r"\bfgets\s*\("), "fgets()", frozenset({"c", "cpp"})),
    (re.compile(r"\bgets\s*\("), "gets()", frozenset({"c", "cpp"})),
    (re.compile(r"\bscanf\s*\("), "scanf()", frozenset({"c", "cpp"})),
    (re.compile(r"\bgetenv\s*\("), "getenv()", frozenset({"c", "cpp"})),
    (re.compile(r"\bread\s*\("), "read()", frozenset({"c", "cpp"})),
    (re.compile(r"\brecv\s*\("), "recv()", frozenset({"c", "cpp"})),

    # PHP
    (re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"), "$_SUPERGLOBAL", frozenset({"php"})),
    (re.compile(r"\bfile_get_contents\s*\(\s*['\"]php://input"), "php://input", frozenset({"php"})),

    # General (all languages)
    (re.compile(r"\bdeserializ[ei]\w*\s*\("), "deserialize()", None),
    (re.compile(r"\bunmarshal\w*\s*\("), "unmarshal()", None),
]


# ---------------------------------------------------------------------------
# Taint sink patterns
# ---------------------------------------------------------------------------

# Each entry: (regex, sink_label, SignalCategory, language_constraint_or_None)
_SINK_PATTERNS: list[tuple[re.Pattern[str], str, SignalCategory, frozenset[str] | None]] = [
    # SQL injection sinks
    (re.compile(r"\bcursor\s*\.\s*execute\s*\("), "cursor.execute", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\bsession\s*\.\s*execute\s*\("), "session.execute", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\btext\s*\(\s*['\"]"), "sqlalchemy.text", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\.\s*execute\s*\(\s*['\"]"), ".execute(sql)", SignalCategory.INJECTION, None),
    (re.compile(r"\.\s*query\s*\(\s*['\"]"), ".query(sql)", SignalCategory.INJECTION, None),

    # Command injection sinks
    (re.compile(r"\bos\s*\.\s*system\s*\("), "os.system", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\bos\s*\.\s*popen\s*\("), "os.popen", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\("), "subprocess", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\beval\s*\("), "eval", SignalCategory.INJECTION, None),
    (re.compile(r"\bexec\s*\("), "exec", SignalCategory.INJECTION, frozenset({"python"})),
    (re.compile(r"\bsystem\s*\("), "system()", SignalCategory.INJECTION, frozenset({"c", "cpp"})),
    (re.compile(r"\bpopen\s*\("), "popen()", SignalCategory.INJECTION, frozenset({"c", "cpp"})),
    (re.compile(r"\bexecv[pe]?\s*\("), "exec*()", SignalCategory.INJECTION, frozenset({"c", "cpp"})),
    (re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b"), "Runtime.exec", SignalCategory.INJECTION, frozenset({"java"})),
    (re.compile(r"\bProcessBuilder\b"), "ProcessBuilder", SignalCategory.INJECTION, frozenset({"java"})),
    (re.compile(r"\bexec\s*\.\s*Command\s*\("), "exec.Command", SignalCategory.INJECTION, frozenset({"go"})),

    # JS injection sinks
    (re.compile(r"\bchild_process\b.*\bexec\s*\("), "child_process.exec", SignalCategory.INJECTION, frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\binnerHTML\s*="), "innerHTML", SignalCategory.INJECTION, frozenset({"javascript", "typescript", "tsx"})),
    (re.compile(r"\bdocument\s*\.\s*write\s*\("), "document.write", SignalCategory.INJECTION, frozenset({"javascript", "typescript", "tsx"})),

    # Memory sinks (C/C++)
    (re.compile(r"\bmemcpy\s*\("), "memcpy", SignalCategory.MEMORY, frozenset({"c", "cpp"})),
    (re.compile(r"\bstrcpy\s*\("), "strcpy", SignalCategory.MEMORY, frozenset({"c", "cpp"})),
    (re.compile(r"\bstrncpy\s*\("), "strncpy", SignalCategory.MEMORY, frozenset({"c", "cpp"})),
    (re.compile(r"\bstrcat\s*\("), "strcat", SignalCategory.MEMORY, frozenset({"c", "cpp"})),
    (re.compile(r"\bsprintf\s*\("), "sprintf", SignalCategory.MEMORY, frozenset({"c", "cpp"})),
    (re.compile(r"\bfree\s*\("), "free", SignalCategory.MEMORY, frozenset({"c", "cpp"})),

    # Auth sinks
    (re.compile(r"\bset_password\s*\("), "set_password", SignalCategory.AUTH, None),
    (re.compile(r"\bcreate_user\s*\("), "create_user", SignalCategory.AUTH, None),
    (re.compile(r"\bsession\s*\["), "session_write", SignalCategory.AUTH, None),

    # Privilege sinks
    (re.compile(r"\bsetuid\s*\("), "setuid", SignalCategory.PRIVILEGE, None),
    (re.compile(r"\bchmod\s*\("), "chmod", SignalCategory.PRIVILEGE, None),
    (re.compile(r"\bchown\s*\("), "chown", SignalCategory.PRIVILEGE, None),

    # Data access sinks (file/network)
    (re.compile(r"\bopen\s*\("), "open()", SignalCategory.DATA_ACCESS, None),
    (re.compile(r"\bsend\s*\("), "send()", SignalCategory.DATA_ACCESS, None),
    (re.compile(r"\bwrite\s*\("), "write()", SignalCategory.DATA_ACCESS, None),
]


# ---------------------------------------------------------------------------
# Sanitizer patterns
# ---------------------------------------------------------------------------

_SANITIZER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bescape\w*\s*\(", re.IGNORECASE), "escape"),
    (re.compile(r"\bsanitize\w*\s*\(", re.IGNORECASE), "sanitize"),
    (re.compile(r"\bvalidate\w*\s*\(", re.IGNORECASE), "validate"),
    (re.compile(r"\bhtml\.escape\s*\("), "html.escape"),
    (re.compile(r"\bmarkup_safe\b", re.IGNORECASE), "markup_safe"),
    (re.compile(r"\bbleach\s*\.\s*clean\s*\("), "bleach.clean"),
    (re.compile(r"\bparameterize\w*\s*\(", re.IGNORECASE), "parameterize"),
    (re.compile(r"\bquote\s*\("), "quote"),
    (re.compile(r"\bshlex\s*\.\s*quote\s*\("), "shlex.quote"),
    (re.compile(r"\bprepare[dD]\s*(Statement|Query)\b"), "prepared_statement"),
    (re.compile(r"\bint\s*\("), "int_cast"),
    (re.compile(r"\bfloat\s*\("), "float_cast"),
    (re.compile(r"\bstrip\w*\s*\("), "strip"),
    (re.compile(r"\bencode\w*\s*\("), "encode"),
    (re.compile(r"\bre\s*\.\s*(match|search|fullmatch)\s*\("), "regex_check"),
    (re.compile(r"\bwhitelist\b", re.IGNORECASE), "whitelist"),
    (re.compile(r"\ballowlist\b", re.IGNORECASE), "allowlist"),
]


# ---------------------------------------------------------------------------
# Assignment tracking (regex-based)
# ---------------------------------------------------------------------------

# Matches simple assignments: var = expr, var := expr
_ASSIGN_PATTERN = re.compile(r"(\w+)\s*[:=]=?\s*(.+)")

# Matches function parameters as initial taint sources
_PARAM_SOURCE_KEYWORDS = frozenset({
    "request", "req", "input", "data", "body", "params", "query",
    "payload", "form", "args", "argv", "user_input", "raw_input",
    "stdin", "environ", "env", "headers", "cookies",
})


def _find_sources_in_function(func: Function) -> list[TaintSource]:
    """Identify taint sources within a function."""
    sources: list[TaintSource] = []
    lines = func.source.splitlines()
    language = func.language

    # 1. Check function parameters as taint sources
    for param in func.parameters:
        param_lower = param.lower()
        for keyword in _PARAM_SOURCE_KEYWORDS:
            if keyword in param_lower:
                sources.append(TaintSource(
                    variable=param,
                    origin=f"parameter:{param}",
                    line=func.start_line,
                ))
                break

    # 2. Check if this is an entry point -- all params are tainted
    if func.is_entry_point:
        for param in func.parameters:
            if not any(s.variable == param for s in sources):
                sources.append(TaintSource(
                    variable=param,
                    origin=f"entry_point_param:{param}",
                    line=func.start_line,
                ))

    # 3. Scan source for taint source patterns
    for line_idx, line in enumerate(lines):
        line_num = func.start_line + line_idx
        for pattern, origin, lang_constraint in _SOURCE_PATTERNS:
            if lang_constraint is not None and language not in lang_constraint:
                continue
            match = pattern.search(line)
            if match:
                # Try to find what variable this is assigned to
                assign_m = _ASSIGN_PATTERN.match(line.strip())
                var_name = assign_m.group(1) if assign_m else origin.replace(".", "_")
                sources.append(TaintSource(
                    variable=var_name,
                    origin=origin,
                    line=line_num,
                ))

    return sources


def _find_sinks_in_function(func: Function) -> list[TaintSink]:
    """Identify taint sinks within a function."""
    sinks: list[TaintSink] = []
    lines = func.source.splitlines()
    language = func.language

    for line_idx, line in enumerate(lines):
        line_num = func.start_line + line_idx
        for pattern, label, category, lang_constraint in _SINK_PATTERNS:
            if lang_constraint is not None and language not in lang_constraint:
                continue
            if pattern.search(line):
                sinks.append(TaintSink(
                    function_call=label,
                    category=category,
                    line=line_num,
                ))

    return sinks


def _find_sanitizers(source: str) -> list[str]:
    """Find sanitizer calls in source code."""
    found: list[str] = []
    for pattern, name in _SANITIZER_PATTERNS:
        if pattern.search(source):
            found.append(name)
    return found


def _propagate_taint(
    func: Function,
    sources: list[TaintSource],
) -> dict[str, list[TaintSource]]:
    """Propagate tainted variables through assignments.

    Returns a mapping of variable_name -> list of TaintSource objects that
    flow into it (transitive).
    """
    # Start with directly tainted variables
    tainted: dict[str, list[TaintSource]] = {}
    for src in sources:
        tainted.setdefault(src.variable, []).append(src)

    lines = func.source.splitlines()

    # Multiple passes to handle transitive assignments
    for _ in range(3):
        changed = False
        for line in lines:
            line_stripped = line.strip()
            # Skip comments
            if line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            assign_m = _ASSIGN_PATTERN.match(line_stripped)
            if not assign_m:
                continue

            target_var = assign_m.group(1)
            rhs = assign_m.group(2)

            # Check if any tainted variable appears in the RHS
            for taint_var in list(tainted.keys()):
                # Word boundary match for tainted variable in RHS
                if re.search(r"\b" + re.escape(taint_var) + r"\b", rhs):
                    if target_var not in tainted:
                        tainted[target_var] = []
                        changed = True
                    # Propagate the source through
                    for src in tainted[taint_var]:
                        if src not in tainted[target_var]:
                            tainted[target_var].append(src)
                            changed = True

        if not changed:
            break

    return tainted


def _check_taint_reaches_sink(
    func: Function,
    tainted: dict[str, list[TaintSource]],
    sink: TaintSink,
) -> list[tuple[TaintSource, list[str]]]:
    """Check if any tainted variable reaches a sink.

    Returns list of (source, intermediate_path) pairs.
    """
    results: list[tuple[TaintSource, list[str]]] = []
    lines = func.source.splitlines()

    # Find the sink line
    sink_line_idx = sink.line - func.start_line
    if 0 <= sink_line_idx < len(lines):
        sink_line = lines[sink_line_idx]
    else:
        # Approximate: search for sink function_call in source
        sink_line = ""
        for line in lines:
            if sink.function_call.split(".")[-1] in line:
                sink_line = line
                break

    # Check if any tainted variable appears on or near the sink line
    for var_name, sources_list in tainted.items():
        if re.search(r"\b" + re.escape(var_name) + r"\b", sink_line):
            for src in sources_list:
                # Build the intermediate path
                path = _trace_intermediate_path(var_name, src.variable, tainted)
                results.append((src, path))
                # Update sink with tainted arg info
                sink.tainted_arg = var_name

    return results


def _trace_intermediate_path(
    final_var: str,
    source_var: str,
    tainted: dict[str, list[TaintSource]],
) -> list[str]:
    """Trace the path from source_var to final_var through tainted map."""
    if final_var == source_var:
        return []

    # Simple BFS through the tainted map to find the path
    visited: set[str] = {source_var}
    queue: list[tuple[str, list[str]]] = [(source_var, [])]

    while queue:
        current, path = queue.pop(0)
        if current == final_var:
            return path

        # Check which variables are tainted by current
        for var, srcs in tainted.items():
            if var not in visited:
                for src in srcs:
                    if src.variable == current or current in (s.variable for s in srcs):
                        visited.add(var)
                        queue.append((var, path + [var]))
                        break

    # Couldn't trace exact path, return just the endpoints
    return [final_var] if final_var != source_var else []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def trace_taint(
    function: Function,
    callers: list[Function] | None = None,
) -> list[TaintPath]:
    """Trace tainted data from sources to sinks within a function and its callers.

    Performs regex-based approximate taint analysis:
    1. Identifies taint sources (user input APIs, parameters from entry points)
    2. Propagates taint through variable assignments
    3. Identifies dangerous sinks
    4. Checks if tainted data reaches sinks
    5. Records any sanitizers in the path
    """
    paths: list[TaintPath] = []

    # Find sources and sinks in the main function
    sources = _find_sources_in_function(function)
    sinks = _find_sinks_in_function(function)
    sanitizers = _find_sanitizers(function.source)

    if not sources or not sinks:
        # Check callers for additional sources if no local sources found
        if not sources and callers:
            for caller in callers:
                caller_sources = _find_sources_in_function(caller)
                if caller_sources:
                    # If a caller has taint sources and calls this function,
                    # treat function parameters as tainted
                    for param in function.parameters:
                        sources.append(TaintSource(
                            variable=param,
                            origin=f"caller:{caller.name}",
                            line=function.start_line,
                        ))
                    break

        if not sources or not sinks:
            return paths

    # Propagate taint through the function
    tainted = _propagate_taint(function, sources)

    # Check each sink for tainted input
    for sink in sinks:
        reaches = _check_taint_reaches_sink(function, tainted, sink)
        for source, intermediate_path in reaches:
            paths.append(TaintPath(
                source=source,
                sink=sink,
                path=intermediate_path,
                sanitizers=sanitizers,
                through_unresolved=False,
            ))

    # If we have callers, also check for cross-function taint
    if callers:
        for caller in callers:
            caller_sources = _find_sources_in_function(caller)
            if not caller_sources:
                continue

            caller_tainted = _propagate_taint(caller, caller_sources)

            # Check if any tainted variable in the caller is passed as an
            # argument to our function (approximate: check if tainted vars
            # appear near our function name in the caller source)
            for taint_var in caller_tainted:
                call_pattern = re.compile(
                    r"\b" + re.escape(function.name) + r"\s*\([^)]*\b"
                    + re.escape(taint_var) + r"\b"
                )
                if call_pattern.search(caller.source):
                    # Tainted data flows from caller into this function
                    for sink in sinks:
                        for src in caller_tainted[taint_var]:
                            paths.append(TaintPath(
                                source=src,
                                sink=sink,
                                path=[taint_var, f"-> {function.name}()"],
                                sanitizers=sanitizers + _find_sanitizers(caller.source),
                                through_unresolved=True,
                            ))

    return paths
