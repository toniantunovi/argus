"""Sanitizer and coverage instrumentation for C/C++ targets."""
from __future__ import annotations

SANITIZER_FLAGS = {
    "asan": "-fsanitize=address -fno-omit-frame-pointer",
    "msan": "-fsanitize=memory -fno-omit-frame-pointer",
    "ubsan": "-fsanitize=undefined -fno-omit-frame-pointer",
    "coverage": "--coverage -fprofile-arcs -ftest-coverage",
}


def get_compile_flags(instrumentation: list[str]) -> str:
    """Get compiler flags for requested instrumentation."""
    flags = []
    for inst in instrumentation:
        if inst in SANITIZER_FLAGS:
            flags.append(SANITIZER_FLAGS[inst])
    return " ".join(flags)


def get_link_flags(instrumentation: list[str]) -> str:
    """Get linker flags for requested instrumentation."""
    flags = []
    for inst in instrumentation:
        if inst in ("asan", "msan", "ubsan"):
            sanitizer_name = {
                "asan": "address",
                "msan": "memory",
                "ubsan": "undefined",
            }[inst]
            flags.append(f"-fsanitize={sanitizer_name}")
    return " ".join(flags)


def parse_sanitizer_output(stderr: str) -> dict | None:
    """Parse ASAN/MSAN/UBSAN output from stderr."""
    if "AddressSanitizer" in stderr or "ERROR: AddressSanitizer" in stderr:
        return _parse_asan(stderr)
    if "MemorySanitizer" in stderr:
        return _parse_msan(stderr)
    if "UndefinedBehaviorSanitizer" in stderr or "runtime error:" in stderr:
        return _parse_ubsan(stderr)
    return None


def _parse_asan(stderr: str) -> dict:
    result = {"sanitizer": "asan", "type": "unknown", "details": ""}
    if "heap-buffer-overflow" in stderr:
        result["type"] = "heap-buffer-overflow"
    elif "stack-buffer-overflow" in stderr:
        result["type"] = "stack-buffer-overflow"
    elif "heap-use-after-free" in stderr:
        result["type"] = "heap-use-after-free"
    elif "double-free" in stderr:
        result["type"] = "double-free"
    elif "stack-overflow" in stderr:
        result["type"] = "stack-overflow"
    result["details"] = stderr
    return result


def _parse_msan(stderr: str) -> dict:
    return {"sanitizer": "msan", "type": "uninitialized-memory-read", "details": stderr}


def _parse_ubsan(stderr: str) -> dict:
    result = {"sanitizer": "ubsan", "type": "undefined-behavior", "details": ""}
    if "integer overflow" in stderr:
        result["type"] = "integer-overflow"
    elif "null pointer" in stderr:
        result["type"] = "null-pointer-dereference"
    elif "alignment" in stderr:
        result["type"] = "misaligned-address"
    result["details"] = stderr
    return result


# ---------------------------------------------------------------------------
# Build-system-specific sanitizer injection helpers
# ---------------------------------------------------------------------------
# These return strings that can be pasted verbatim into a Claw prompt so the
# agent knows the exact commands for each build system.

def get_cmake_sanitizer_args(instrumentation: list[str]) -> str:
    """Return cmake CLI args that inject sanitizer flags."""
    cflags = get_compile_flags(instrumentation)
    lflags = get_link_flags(instrumentation)
    parts = [f'-DCMAKE_C_FLAGS="{cflags} -g"', f'-DCMAKE_CXX_FLAGS="{cflags} -g"']
    if lflags:
        parts.append(f'-DCMAKE_EXE_LINKER_FLAGS="{lflags}"')
    return " ".join(parts)


def get_autotools_sanitizer_env(instrumentation: list[str]) -> str:
    """Return environment prefix for autotools configure scripts."""
    cflags = get_compile_flags(instrumentation)
    lflags = get_link_flags(instrumentation)
    return f'CFLAGS="{cflags} -g" CXXFLAGS="{cflags} -g" LDFLAGS="{lflags}"'


def get_meson_sanitizer_args(instrumentation: list[str]) -> str:
    """Return meson setup args for sanitizer instrumentation."""
    sanitizers = []
    for inst in instrumentation:
        if inst == "asan":
            sanitizers.append("address")
        elif inst == "ubsan":
            sanitizers.append("undefined")
        elif inst == "msan":
            sanitizers.append("memory")
    if not sanitizers:
        return ""
    return f'-Db_sanitize={",".join(sanitizers)}'


def get_make_sanitizer_override(instrumentation: list[str]) -> str:
    """Return make command-line variable overrides for sanitizer flags."""
    cflags = get_compile_flags(instrumentation)
    lflags = get_link_flags(instrumentation)
    return f'CFLAGS="{cflags} -g" CXXFLAGS="{cflags} -g" LDFLAGS="{lflags}"'
