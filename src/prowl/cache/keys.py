"""Cache key computation."""
from __future__ import annotations

import hashlib

from prowl.models.core import Function


def compute_hypothesis_key(func: Function, rubric_version: str = "1.0") -> str:
    """Compute cache key for hypothesis/triage results."""
    content = func.source + "||" + "||".join(sorted(func.callers[:5])) + "||" + rubric_version
    return hashlib.sha256(content.encode()).hexdigest()[:16]

def compute_exploit_key(func: Function, exploit_type: str, sandbox_hash: str = "", rubric_version: str = "1.0") -> str:
    """Compute cache key for exploit/PoC results."""
    content = func.source + "||" + exploit_type + "||" + sandbox_hash + "||" + rubric_version
    return hashlib.sha256(content.encode()).hexdigest()[:16]

def compute_caller_interface_signature(func: Function) -> str:
    """Compute a signature of how callers invoke this function."""
    parts = sorted(func.callers[:10])
    return hashlib.sha256("||".join(parts).encode()).hexdigest()[:8]
