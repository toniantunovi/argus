"""Cross-cutting cache invalidation for middleware, dependency, and framework changes."""
from __future__ import annotations

import logging
from pathlib import Path

from prowl.cache.store import CacheStore

logger = logging.getLogger(__name__)

def check_cross_cutting_invalidation(cache: CacheStore, project_root: Path, previous_state: dict | None = None) -> list[str]:
    """Check for cross-cutting changes that require broader invalidation.
    Returns list of invalidation reasons.
    """
    reasons = []

    if previous_state is None:
        return reasons

    # Check middleware changes
    middleware_files = _get_middleware_files(project_root)
    for mf in middleware_files:
        current_hash = _file_hash(mf)
        prev_hash = previous_state.get("middleware_hashes", {}).get(str(mf))
        if prev_hash and current_hash != prev_hash:
            count = cache.invalidate_by_category(["auth", "input", "injection"])
            reasons.append(f"Middleware change in {mf.name}: invalidated {count} entries")

    # Check framework version changes
    lockfiles = ["requirements.txt", "package-lock.json", "Gemfile.lock", "go.sum", "Cargo.lock"]
    for lf_name in lockfiles:
        lf = project_root / lf_name
        if lf.exists():
            current_hash = _file_hash(lf)
            prev_hash = previous_state.get("lockfile_hashes", {}).get(lf_name)
            if prev_hash and current_hash != prev_hash:
                # Check if security-relevant packages changed
                if _has_security_dep_change(lf, previous_state.get("lockfile_contents", {}).get(lf_name, "")):
                    count = cache.invalidate_by_category(["auth", "crypto", "injection", "input"])
                    reasons.append(f"Security dependency change in {lf_name}: invalidated {count} entries")

    # Check build config changes
    build_files = ["Makefile", "CMakeLists.txt", "tsconfig.json"]
    for bf_name in build_files:
        bf = project_root / bf_name
        if bf.exists():
            current_hash = _file_hash(bf)
            prev_hash = previous_state.get("build_hashes", {}).get(bf_name)
            if prev_hash and current_hash != prev_hash:
                count = cache.invalidate_by_category(["memory"])
                reasons.append(f"Build config change in {bf_name}: invalidated {count} entries")

    return reasons

def capture_state(project_root: Path) -> dict:
    """Capture current project state for future cross-cutting comparison."""
    state: dict = {
        "middleware_hashes": {},
        "lockfile_hashes": {},
        "lockfile_contents": {},
        "build_hashes": {},
    }

    for mf in _get_middleware_files(project_root):
        state["middleware_hashes"][str(mf)] = _file_hash(mf)

    for lf_name in ["requirements.txt", "package-lock.json", "Gemfile.lock", "go.sum", "Cargo.lock"]:
        lf = project_root / lf_name
        if lf.exists():
            state["lockfile_hashes"][lf_name] = _file_hash(lf)
            state["lockfile_contents"][lf_name] = lf.read_text(errors="ignore")[:10000]

    for bf_name in ["Makefile", "CMakeLists.txt", "tsconfig.json"]:
        bf = project_root / bf_name
        if bf.exists():
            state["build_hashes"][bf_name] = _file_hash(bf)

    return state

def _get_middleware_files(project_root: Path) -> list[Path]:
    """Find middleware configuration files."""
    candidates = [
        project_root / "settings.py",  # Django
        project_root / "config" / "settings.py",
        project_root / "app.js",  # Express
        project_root / "server.js",
    ]
    # Also search for Django MIDDLEWARE settings
    results = []
    for c in candidates:
        if c.exists():
            results.append(c)
    # Search for middleware directories
    for mw_dir in (project_root / "middleware", project_root / "src" / "middleware"):
        if mw_dir.is_dir():
            results.extend(mw_dir.glob("*.py"))
            results.extend(mw_dir.glob("*.js"))
            results.extend(mw_dir.glob("*.ts"))
    return results

def _file_hash(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]

def _has_security_dep_change(lockfile: Path, previous_content: str) -> bool:
    """Check if security-relevant dependencies changed."""
    security_packages = [
        "django", "flask", "express", "spring", "rails",
        "bcrypt", "argon2", "jwt", "oauth", "passport",
        "helmet", "csrf", "sanitize", "escape", "crypto",
    ]
    current = lockfile.read_text(errors="ignore").lower()
    previous = previous_content.lower()
    for pkg in security_packages:
        if (pkg in current) != (pkg in previous):
            return True
        # Check version changes for security packages
        # Simplified: if the package line differs
    return False
