"""Project type detection: application, library, or mixed."""
from __future__ import annotations

from pathlib import Path

from argus.models.core import ProjectType


def detect_project_type(
    project_root: Path, functions: list | None = None
) -> ProjectType:
    """Detect project type from project structure and function analysis."""
    has_app_indicators = _has_application_indicators(project_root)
    has_lib_indicators = _has_library_indicators(project_root)
    has_entry_points = False
    if functions:
        has_entry_points = any(
            getattr(f, "is_entry_point", False) for f in functions
        )

    if has_app_indicators and has_lib_indicators:
        return ProjectType.MIXED
    if has_app_indicators or has_entry_points:
        return ProjectType.APPLICATION
    if has_lib_indicators:
        return ProjectType.LIBRARY
    return ProjectType.APPLICATION  # default


# ---------------------------------------------------------------------------
# Application indicators
# ---------------------------------------------------------------------------

# Framework routing/config files
_APP_FILE_PATTERNS: list[str] = [
    # Python frameworks
    "urls.py",           # Django
    "wsgi.py",           # Django / WSGI
    "asgi.py",           # ASGI
    "manage.py",         # Django
    "app.py",            # Flask / generic
    "main.py",           # Generic entry point
    "server.py",         # Generic server
    "settings.py",       # Django settings

    # Docker
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",

    # Process managers
    "Procfile",          # Heroku / foreman
    "supervisord.conf",

    # Kubernetes
    "deployment.yaml",
    "deployment.yml",
]

# Directory-level glob patterns indicating an application
_APP_DIR_PATTERNS: list[str] = [
    # Python Django
    "**/urls.py",
    "**/views.py",
    "**/wsgi.py",
    "**/asgi.py",

    # Express / Node
    "**/routes/**",
    "**/controllers/**",

    # Spring / Java
    "**/controller/**",
    "**/Controller.java",
    "**/*Controller.java",

    # Go
    "**/cmd/**",
    "**/handler/**",
    "**/handlers/**",
]


def _has_application_indicators(project_root: Path) -> bool:
    """Check for framework routing files, main() functions, Docker files, etc."""
    # Check for known application files at the root
    for name in _APP_FILE_PATTERNS:
        if (project_root / name).exists():
            return True

    # Check for directory-level patterns (shallow search for performance)
    for pattern in _APP_DIR_PATTERNS:
        matches = list(project_root.glob(pattern))
        if matches:
            return True

    # Check for package.json with a start script (Node.js app)
    package_json = project_root / "package.json"
    if package_json.exists():
        try:
            import json

            data = json.loads(package_json.read_text(errors="ignore"))
            scripts = data.get("scripts", {})
            if "start" in scripts or "serve" in scripts or "dev" in scripts:
                return True
            # Check for server-related main/bin entry points
            main = data.get("main", "")
            if any(kw in main.lower() for kw in ("server", "app", "index")):
                return True
        except (ValueError, OSError):
            pass

    # Check for pyproject.toml with scripts
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(errors="ignore")
            if "[project.scripts]" in content or "[tool.poetry.scripts]" in content:
                return True
            if "[project.gui-scripts]" in content:
                return True
        except OSError:
            pass

    # Check for Cargo.toml with [[bin]]
    cargo_toml = project_root / "Cargo.toml"
    if cargo_toml.exists():
        try:
            content = cargo_toml.read_text(errors="ignore")
            if "[[bin]]" in content:
                return True
            # Default binary: src/main.rs
            if (project_root / "src" / "main.rs").exists():
                return True
        except OSError:
            pass

    # Check for Go cmd/ directory or main.go
    if (project_root / "cmd").is_dir():
        return True
    if (project_root / "main.go").exists():
        return True

    return False


# ---------------------------------------------------------------------------
# Library indicators
# ---------------------------------------------------------------------------

_LIB_FILES: list[str] = [
    # Python
    "setup.py",
    "setup.cfg",

    # Ruby
    "*.gemspec",
]

_LIB_GLOB_PATTERNS: list[str] = [
    "*.gemspec",
]


def _has_library_indicators(project_root: Path) -> bool:
    """Check for library packaging metadata."""
    # Python: setup.py / setup.cfg
    if (project_root / "setup.py").exists():
        return True
    setup_cfg = project_root / "setup.cfg"
    if setup_cfg.exists():
        try:
            content = setup_cfg.read_text(errors="ignore")
            # Library if it has [metadata] section with name
            if "[metadata]" in content:
                return True
        except OSError:
            pass

    # Python: pyproject.toml without scripts (pure library)
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(errors="ignore")
            has_project = "[project]" in content or "[tool.poetry]" in content
            has_scripts = (
                "[project.scripts]" in content
                or "[tool.poetry.scripts]" in content
                or "[project.gui-scripts]" in content
            )
            if has_project and not has_scripts:
                return True
        except OSError:
            pass

    # Rust: Cargo.toml with [lib]
    cargo_toml = project_root / "Cargo.toml"
    if cargo_toml.exists():
        try:
            content = cargo_toml.read_text(errors="ignore")
            if "[lib]" in content:
                return True
            # Default library: src/lib.rs without src/main.rs
            if (project_root / "src" / "lib.rs").exists() and not (
                project_root / "src" / "main.rs"
            ).exists():
                return True
        except OSError:
            pass

    # Node: package.json without server-like main
    package_json = project_root / "package.json"
    if package_json.exists():
        try:
            import json

            data = json.loads(package_json.read_text(errors="ignore"))
            # Has "main" or "exports" but no "start" script => probably a library
            has_exports = "main" in data or "exports" in data or "module" in data
            scripts = data.get("scripts", {})
            has_start = "start" in scripts or "serve" in scripts
            if has_exports and not has_start:
                return True
        except (ValueError, OSError):
            pass

    # Ruby gemspec
    for match in project_root.glob("*.gemspec"):
        if match.is_file():
            return True

    # Go: no cmd/ and no main.go but has go.mod
    go_mod = project_root / "go.mod"
    if go_mod.exists():
        has_cmd = (project_root / "cmd").is_dir()
        has_main = (project_root / "main.go").exists()
        if not has_cmd and not has_main:
            return True

    return False
