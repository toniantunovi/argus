"""Shared-state interaction target grouping."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from argus.models.core import Function, SignalCategory

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InteractionTarget:
    group_id: str
    shared_state_type: str  # session, database, global, filesystem, cache
    shared_key: str  # the shared key/table/variable
    functions: list[Function] = field(default_factory=list)

    @property
    def has_high_weight_signals(self) -> bool:
        high_weight = {SignalCategory.AUTH, SignalCategory.FINANCIAL, SignalCategory.PRIVILEGE}
        for func in self.functions:
            for sig in func.signals:
                if sig.category in high_weight:
                    return True
        return False


# ---------------------------------------------------------------------------
# Shared-state extraction patterns
# ---------------------------------------------------------------------------

# Session keys: session["key"], session.get("key"), request.session["key"]
_SESSION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""session\s*\[\s*['"]([^'"]+)['"]\s*\]"""),
    re.compile(r"""session\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""session\s*\.\s*set\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""session\s*\.\s*pop\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""session\s*\.\s*delete\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""request\s*\.\s*session\s*\[\s*['"]([^'"]+)['"]\s*\]"""),
    re.compile(r"""request\s*\.\s*session\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""session\s*\.\s*setAttribute\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""session\s*\.\s*getAttribute\s*\(\s*['"]([^'"]+)['"]"""),
]

# Cache keys: cache.get("key"), cache.set("key", ...), redis.get("key")
_CACHE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""cache\s*\.\s*(?:get|set|delete|remove|invalidate|has)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""redis\s*\.\s*(?:get|set|hget|hset|del|exists|setex|setnx|lpush|rpush|lrange)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""memcache[d]?\s*\.\s*(?:get|set|delete|add|replace)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""cache_(?:get|set|delete|clear)\s*\(\s*['"]([^'"]+)['"]"""),
]

# Database tables: SQL table names, ORM model references
_DB_PATTERNS: list[re.Pattern[str]] = [
    # SQL: SELECT ... FROM table, INSERT INTO table, UPDATE table SET, DELETE FROM table
    re.compile(r"""\bFROM\s+['"`]?(\w+)['"`]?""", re.IGNORECASE),
    re.compile(r"""\bINTO\s+['"`]?(\w+)['"`]?""", re.IGNORECASE),
    re.compile(r"""\bUPDATE\s+['"`]?(\w+)['"`]?\s+SET\b""", re.IGNORECASE),
    re.compile(r"""\bDELETE\s+FROM\s+['"`]?(\w+)['"`]?""", re.IGNORECASE),
    re.compile(r"""\bJOIN\s+['"`]?(\w+)['"`]?""", re.IGNORECASE),

    # ORM model references: Model.objects, Model.query, Model.find
    re.compile(r"""(\w+)\s*\.\s*objects\s*\."""),
    re.compile(r"""(\w+)\s*\.\s*query\s*\."""),

    # SQLAlchemy: session.query(Model)
    re.compile(r"""session\s*\.\s*query\s*\(\s*(\w+)\s*\)"""),

    # Prisma: prisma.model.find/create/update/delete
    re.compile(r"""prisma\s*\.\s*(\w+)\s*\.\s*(?:find|create|update|delete|upsert)"""),

    # Sequelize: Model.findAll, Model.create, etc.
    re.compile(r"""(\w+)\s*\.\s*(?:findAll|findOne|findByPk|create|bulkCreate|update|destroy)\s*\("""),

    # Mongoose: Model.find, Model.findById, Model.save
    re.compile(r"""(\w+)\s*\.\s*(?:find|findById|findOne|aggregate|countDocuments|distinct)\s*\("""),
]

# SQL keywords to filter out from DB table name matches
_SQL_KEYWORDS = frozenset({
    "select", "from", "where", "and", "or", "not", "in", "exists",
    "having", "group", "order", "by", "limit", "offset", "as", "on",
    "inner", "outer", "left", "right", "cross", "natural", "join",
    "union", "intersect", "except", "all", "distinct", "case", "when",
    "then", "else", "end", "null", "true", "false", "is", "like",
    "between", "set", "values", "into", "table", "create", "drop",
    "alter", "index", "view", "trigger", "function", "procedure",
    "begin", "commit", "rollback", "transaction", "cascade",
})

# Global variable patterns
_GLOBAL_PATTERNS: list[re.Pattern[str]] = [
    # Python: global var
    re.compile(r"""\bglobal\s+(\w+)"""),
    # Module-level assignment with ALL_CAPS (convention for constants/globals)
    re.compile(r"""^([A-Z][A-Z_0-9]+)\s*=""", re.MULTILINE),
    # Go: package-level var access
    re.compile(r"""(\w+)\s*\.\s*(?:Lock|Unlock|RLock|RUnlock)\s*\("""),
]

# File path patterns
_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""open\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""(?:readFile|writeFile|appendFile)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""(?:os|ioutil|filepath)\s*\.\s*(?:Open|Create|ReadFile|WriteFile|Remove|Mkdir)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""fopen\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""Path\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""with\s+open\s*\(\s*['"]([^'"]+)['"]"""),
]


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_shared_keys(func: Function) -> list[tuple[str, str]]:
    """Extract (shared_state_type, shared_key) pairs from a function's source.

    Returns a list of (type, key) tuples.
    """
    results: list[tuple[str, str]] = []
    source = func.source

    # Session keys
    for pattern in _SESSION_PATTERNS:
        for m in pattern.finditer(source):
            key = m.group(1)
            results.append(("session", key))

    # Cache keys
    for pattern in _CACHE_PATTERNS:
        for m in pattern.finditer(source):
            key = m.group(1)
            results.append(("cache", key))

    # Database tables
    for pattern in _DB_PATTERNS:
        for m in pattern.finditer(source):
            table = m.group(1)
            if table.lower() not in _SQL_KEYWORDS and len(table) > 1:
                results.append(("database", table))

    # Global variables
    for pattern in _GLOBAL_PATTERNS:
        for m in pattern.finditer(source):
            var = m.group(1)
            if len(var) > 1:
                results.append(("global", var))

    # File paths
    for pattern in _FILE_PATTERNS:
        for m in pattern.finditer(source):
            path = m.group(1)
            if path and len(path) > 1:
                results.append(("filesystem", path))

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_interaction_targets(functions: list[Function]) -> list[InteractionTarget]:
    """Detect groups of functions operating on shared state.

    Scans each function for references to shared state (session keys, cache
    keys, database tables, global variables, file paths) and groups functions
    that reference the same key together into InteractionTarget objects.

    Only groups with 2+ functions are returned (a single function accessing
    a key is not an interaction).
    """
    # Map (state_type, key) -> list of functions
    key_to_functions: dict[tuple[str, str], list[Function]] = defaultdict(list)

    for func in functions:
        keys = _extract_shared_keys(func)
        seen_keys: set[tuple[str, str]] = set()
        for state_type, key in keys:
            composite = (state_type, key)
            if composite not in seen_keys:
                seen_keys.add(composite)
                key_to_functions[composite].append(func)

    # Build InteractionTarget objects for groups with 2+ functions
    targets: list[InteractionTarget] = []
    for (state_type, key), funcs in key_to_functions.items():
        if len(funcs) < 2:
            continue

        group_id = f"{state_type}:{key}"
        targets.append(InteractionTarget(
            group_id=group_id,
            shared_state_type=state_type,
            shared_key=key,
            functions=funcs,
        ))

    # Sort by number of functions (largest groups first), then by whether
    # high-weight signals are present
    targets.sort(
        key=lambda t: (t.has_high_weight_signals, len(t.functions)),
        reverse=True,
    )

    return targets
