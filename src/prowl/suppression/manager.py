"""Suppression CRUD: suppress, match, orphan detection."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

class Suppression(BaseModel):
    finding_id: str
    stable_id: str = ""
    suppressed: bool = True
    suppressed_by: str = "user"
    reason: str = ""
    suppressed_at: str = ""
    suppress_scope: str = "finding"  # finding, function, rule, project
    category: str = ""
    file_path: str = ""
    function_name: str = ""

class SuppressionManager:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.prowl_dir = project_root / ".prowl"
        self.prowl_dir.mkdir(parents=True, exist_ok=True)
        self.suppressions_file = self.prowl_dir / "suppressions.json"
        self.suppressions = self._load()

    def _load(self) -> list[Suppression]:
        if self.suppressions_file.exists():
            try:
                data = json.loads(self.suppressions_file.read_text())
                return [Suppression.model_validate(s) for s in data]
            except (json.JSONDecodeError, Exception):
                return []
        return []

    def _save(self) -> None:
        data = [s.model_dump() for s in self.suppressions]
        self.suppressions_file.write_text(json.dumps(data, indent=2))

    def suppress(self, finding_id: str, reason: str, scope: str = "finding",
                 stable_id: str = "", category: str = "", file_path: str = "", function_name: str = "") -> None:
        """Suppress a finding."""
        # Parse finding_id to extract metadata if not provided
        if not stable_id and "::" not in finding_id:
            # Try to derive stable_id from finding_id
            # Format: prowl-{category}-{file}-{line}
            parts = finding_id.split("-", 2)
            if len(parts) >= 3:
                category = category or parts[1]

        suppression = Suppression(
            finding_id=finding_id,
            stable_id=stable_id or finding_id,
            reason=reason,
            suppress_scope=scope,
            suppressed_at=datetime.now(timezone.utc).isoformat() + "Z",
            category=category,
            file_path=file_path,
            function_name=function_name,
        )

        # Remove any existing suppression for this ID
        self.suppressions = [s for s in self.suppressions if s.finding_id != finding_id]
        self.suppressions.append(suppression)
        self._save()
        logger.info(f"Suppressed {finding_id} (scope: {scope})")

    def is_suppressed(self, finding) -> bool:
        """Check if a finding is suppressed by any active suppression."""
        for sup in self.suppressions:
            if not sup.suppressed:
                continue

            if sup.suppress_scope == "finding":
                if sup.finding_id == finding.finding_id or sup.stable_id == finding.stable_id:
                    return True

            elif sup.suppress_scope == "function":
                if sup.stable_id == finding.stable_id:
                    return True
                if sup.function_name and sup.function_name == finding.function_name:
                    if not sup.file_path or sup.file_path == finding.file_path:
                        return True

            elif sup.suppress_scope == "rule":
                if sup.category == finding.category.value and sup.file_path == finding.file_path:
                    return True

            elif sup.suppress_scope == "project":
                if sup.category == finding.category.value:
                    return True

        return False

    def unsuppress(self, finding_id: str) -> bool:
        """Remove suppression for a finding."""
        for sup in self.suppressions:
            if sup.finding_id == finding_id:
                sup.suppressed = False
                self._save()
                return True
        return False

    def detect_orphans(self, current_findings: list) -> list[Suppression]:
        """Find suppressions that don't match any current finding."""
        current_stable_ids = {f.stable_id for f in current_findings}
        current_finding_ids = {f.finding_id for f in current_findings}

        orphans = []
        for sup in self.suppressions:
            if not sup.suppressed:
                continue
            if sup.stable_id not in current_stable_ids and sup.finding_id not in current_finding_ids:
                orphans.append(sup)

        return orphans

    def get_suppression_reasons(self, function_name: str, file_path: str) -> list[str]:
        """Get suppression reasons for a function (for feedback loop in context builder)."""
        reasons = []
        for sup in self.suppressions:
            if sup.function_name == function_name and (not sup.file_path or sup.file_path == file_path):
                reasons.append(sup.reason)
        return reasons

    def filter_findings(self, findings: list) -> list:
        """Filter out suppressed findings."""
        return [f for f in findings if not self.is_suppressed(f)]

    def check_content_similarity(self, old_content: str, new_content: str) -> float:
        """Compute normalized edit distance similarity for carry-over."""
        if not old_content or not new_content:
            return 0.0
        # Simple similarity: ratio of matching characters
        shorter = min(len(old_content), len(new_content))
        longer = max(len(old_content), len(new_content))
        if longer == 0:
            return 1.0
        matches = sum(1 for a, b in zip(old_content, new_content) if a == b)
        return matches / longer
