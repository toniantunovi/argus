"""Sanitizer detection in data flow paths."""
from __future__ import annotations

import re

from argus.models.core import Function

SANITIZER_PATTERNS = [
    # Escaping
    (re.compile(r"\bescape[_a-z]*\(", re.I), "HTML/string escaping"),
    (re.compile(r"\bsanitize[_a-z]*\(", re.I), "Input sanitization"),
    (re.compile(r"\bclean[_a-z]*\(", re.I), "Input cleaning"),
    (re.compile(r"\bstrip_tags\(", re.I), "HTML tag stripping"),
    (re.compile(r"\bhtmlspecialchars\(", re.I), "HTML special chars encoding"),
    (re.compile(r"\bencodeURI(Component)?\(", re.I), "URI encoding"),
    # Validation
    (re.compile(r"\bvalidate[_a-z]*\(", re.I), "Input validation"),
    (re.compile(r"\bcheck[_a-z]*\(", re.I), "Input checking"),
    (re.compile(r"\bverify[_a-z]*\(", re.I), "Input verification"),
    (re.compile(r"\bis_valid\(", re.I), "Validity check"),
    # SQL parameterization
    (re.compile(r"\bprepare[d_]*\(", re.I), "Prepared statement"),
    (re.compile(r"\bparameterize[d]*\(", re.I), "Query parameterization"),
    (re.compile(r"%s|:\w+|\$\d+|\?", re.I), "Parameterized query placeholder"),
    # Bounds checking
    (re.compile(r"\blen\(|\.length\b|\.size\(\)|sizeof\("), "Length/size check"),
    (re.compile(r"\bmin\(|max\(|clamp\("), "Value clamping"),
    (re.compile(r"\bif\s+.*[<>]=?\s*\d+|bounds_check"), "Bounds checking"),
    # Type casting
    (re.compile(r"\bint\(|parseInt\(|Integer\.parseInt\(|atoi\("), "Integer casting"),
    (re.compile(r"\bfloat\(|parseFloat\(|Double\.parseDouble\("), "Float casting"),
]


def find_sanitizers_in_path(func: Function, call_chain: list[str], all_functions: dict[str, Function] | None = None) -> list[str]:
    """Find sanitizers between source and sink in the call chain."""
    sanitizers = []
    # Check the call chain sources
    for source in call_chain:
        for pattern, description in SANITIZER_PATTERNS:
            if pattern.search(source):
                sanitizers.append(description)
    # Check callees of the target function
    if all_functions:
        for callee_name in func.callees:
            for fid, f in all_functions.items():
                if f.name == callee_name or fid == callee_name:
                    for pattern, description in SANITIZER_PATTERNS:
                        if pattern.search(f.source):
                            sanitizers.append(f"in {f.name}(): {description}")
    return list(dict.fromkeys(sanitizers))  # deduplicate preserving order
