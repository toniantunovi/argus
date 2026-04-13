"""Tree-sitter multi-language parsing.

Supports two strategies for obtaining language grammars:

1. tree-sitter-language-pack (preferred) -- provides ``get_parser()`` which
   returns a pre-configured ``tree_sitter.Parser``.  Requires a one-time
   grammar download per language.
2. Individual ``tree-sitter-<lang>`` packages (fallback) -- each package
   exposes a ``language()`` function returning a PyCapsule that is wrapped
   into ``tree_sitter.Language`` and fed to a new ``tree_sitter.Parser``.

The module tries strategy 1 first, then falls back to strategy 2.
"""
from __future__ import annotations

import importlib
from functools import lru_cache
from pathlib import Path

import tree_sitter

# ---------------------------------------------------------------------------
# Extension -> language mapping
# ---------------------------------------------------------------------------

EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
}

# Map from our language names to the individual tree-sitter-<pkg> package names.
# Most are simply ``tree_sitter_<lang>`` but a few differ.
_INDIVIDUAL_PACKAGE_MAP: dict[str, str] = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "tsx": "tree_sitter_typescript",
    "java": "tree_sitter_java",
    "go": "tree_sitter_go",
    "rust": "tree_sitter_rust",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "ruby": "tree_sitter_ruby",
    "php": "tree_sitter_php",
}

# For typescript package, language_typescript() vs language_tsx()
_INDIVIDUAL_FUNC_MAP: dict[str, str] = {
    "typescript": "language_typescript",
    "tsx": "language_tsx",
    "php": "language_php",
}


# ---------------------------------------------------------------------------
# Language / Parser acquisition
# ---------------------------------------------------------------------------

@lru_cache(maxsize=32)
def _get_language(language: str) -> tree_sitter.Language | None:
    """Obtain a ``tree_sitter.Language`` for *language*.

    Tries tree-sitter-language-pack first, then individual packages.
    Returns ``None`` if neither approach succeeds.  The result is cached
    because Language objects are immutable and safe to share.
    """
    # Strategy 1: tree-sitter-language-pack
    try:
        import tree_sitter_language_pack as tslp  # noqa: F811

        return tslp.get_language(language)
    except Exception:
        pass

    # Strategy 2: individual tree-sitter-<lang> packages
    pkg_name = _INDIVIDUAL_PACKAGE_MAP.get(language)
    if pkg_name is None:
        return None

    try:
        mod = importlib.import_module(pkg_name)
    except ImportError:
        return None

    func_name = _INDIVIDUAL_FUNC_MAP.get(language, "language")
    lang_func = getattr(mod, func_name, None)
    if lang_func is None:
        return None

    try:
        capsule = lang_func()
        return tree_sitter.Language(capsule)
    except Exception:
        return None


def _get_parser(language: str) -> tree_sitter.Parser | None:
    """Create a fresh ``tree_sitter.Parser`` for *language*.

    A new Parser is created on every call because Parser objects are
    stateful (they cache the previous tree for incremental parsing).
    Reusing a single cached Parser across unrelated files can produce
    incorrect parse trees.
    """
    lang_obj = _get_language(language)
    if lang_obj is None:
        return None
    try:
        return tree_sitter.Parser(lang_obj)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_language(file_path: Path) -> str | None:
    """Detect programming language from file extension."""
    return EXTENSION_MAP.get(file_path.suffix.lower())


def parse_file(
    file_path: Path, language: str | None = None
) -> tuple[tree_sitter.Tree, str] | None:
    """Parse a file with tree-sitter.

    Returns ``(tree, language)`` or ``None`` if unsupported or on error.
    """
    if language is None:
        language = detect_language(file_path)
    if language is None:
        return None
    parser = _get_parser(language)
    if parser is None:
        return None
    try:
        source = file_path.read_bytes()
        tree = parser.parse(source)
        return tree, language
    except Exception:
        return None


def parse_source(source: bytes, language: str) -> tree_sitter.Tree | None:
    """Parse source bytes with tree-sitter."""
    parser = _get_parser(language)
    if parser is None:
        return None
    try:
        return parser.parse(source)
    except Exception:
        return None
