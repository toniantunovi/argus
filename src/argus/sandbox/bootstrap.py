"""Application bootstrapping: tier classification, dependency detection, environment synthesis."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class BootstrapTier(enum.IntEnum):
    TIER1_SELF_CONTAINED = 1
    TIER2_SINGLE_DB = 2
    TIER3_MULTIPLE_SERVICES = 3
    TIER4_COMPLEX = 4


@dataclass
class BootstrapResult:
    tier: BootstrapTier
    env_vars: dict[str, str] = field(default_factory=dict)
    services: list[str] = field(default_factory=list)
    lockfile: str | None = None
    startup_command: str | None = None
    health_check: str | None = None
    error: str | None = None


def classify_tier(project_root: Path) -> BootstrapTier:
    """Classify project into complexity tiers based on dependencies."""
    has_db = _has_database(project_root)
    has_cache = _has_cache_service(project_root)
    has_mq = _has_message_queue(project_root)
    has_external = _has_external_services(project_root)

    if has_external:
        return BootstrapTier.TIER4_COMPLEX
    if has_db and (has_cache or has_mq):
        return BootstrapTier.TIER3_MULTIPLE_SERVICES
    if has_db:
        return BootstrapTier.TIER2_SINGLE_DB
    return BootstrapTier.TIER1_SELF_CONTAINED


def synthesize_environment(project_root: Path, tier: BootstrapTier) -> BootstrapResult:
    """Synthesize minimal environment for running the target."""
    result = BootstrapResult(tier=tier)

    # Detect lockfile
    for lockfile_name in ["requirements.txt", "package-lock.json", "Gemfile.lock", "go.sum", "Cargo.lock"]:
        lockfile_path = project_root / lockfile_name
        if lockfile_path.exists():
            result.lockfile = lockfile_name
            break

    # Generate environment variables
    result.env_vars = {
        "ARGUS_MODE": "testing",
        "SECRET_KEY": "ARGUS_PLACEHOLDER",
        "DEBUG": "1",
    }

    if tier >= BootstrapTier.TIER2_SINGLE_DB:
        result.env_vars["DATABASE_URL"] = "sqlite:///test.db"
        result.services.append("sqlite")

    if tier >= BootstrapTier.TIER3_MULTIPLE_SERVICES:
        result.env_vars["REDIS_URL"] = "redis://localhost:6379"
        result.services.append("redis")

    # Detect startup command
    result.startup_command = _detect_startup_command(project_root)
    result.health_check = _detect_health_check(project_root)

    return result


def _has_database(root: Path) -> bool:
    """Check if project uses a database."""
    markers = ["requirements.txt", "package.json", "Gemfile", "go.mod"]
    db_patterns = ["psycopg", "mysql", "sqlite", "sqlalchemy", "django", "sequelize", "mongoose", "pg ", "typeorm", "prisma"]
    for marker in markers:
        p = root / marker
        if p.exists():
            content = p.read_text(errors="ignore").lower()
            if any(pat in content for pat in db_patterns):
                return True
    return False


def _has_cache_service(root: Path) -> bool:
    markers = ["requirements.txt", "package.json", "Gemfile"]
    patterns = ["redis", "memcached", "celery"]
    for marker in markers:
        p = root / marker
        if p.exists():
            content = p.read_text(errors="ignore").lower()
            if any(pat in content for pat in patterns):
                return True
    return False


def _has_message_queue(root: Path) -> bool:
    markers = ["requirements.txt", "package.json"]
    patterns = ["rabbitmq", "kafka", "celery", "bull", "amqp"]
    for marker in markers:
        p = root / marker
        if p.exists():
            content = p.read_text(errors="ignore").lower()
            if any(pat in content for pat in patterns):
                return True
    return False


def _has_external_services(root: Path) -> bool:
    """Check for cloud/external service dependencies."""
    markers = ["requirements.txt", "package.json"]
    patterns = ["boto3", "aws-sdk", "google-cloud", "@google-cloud", "azure"]
    for marker in markers:
        p = root / marker
        if p.exists():
            content = p.read_text(errors="ignore").lower()
            if any(pat in content for pat in patterns):
                return True
    return False


def _detect_startup_command(root: Path) -> str | None:
    if (root / "manage.py").exists():
        return "python manage.py runserver 0.0.0.0:8000"
    if (root / "app.py").exists():
        return "python app.py"
    if (root / "server.js").exists():
        return "node server.js"
    if (root / "index.js").exists():
        return "node index.js"
    if (root / "main.go").exists():
        return "go run main.go"
    return None


def _detect_health_check(root: Path) -> str | None:
    return "http://localhost:8000/health"
