"""False negative reporting and diagnosis."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

class MissedVuln(BaseModel):
    file: str
    line: int
    function: str = ""
    category: str
    description: str
    reported_at: str = ""
    diagnosis: dict | None = None

class MissedVulnManager:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.argus_dir = project_root / ".argus"
        self.argus_dir.mkdir(parents=True, exist_ok=True)
        self.missed_file = self.argus_dir / "missed.json"
        self.missed = self._load()

    def _load(self) -> list[MissedVuln]:
        if self.missed_file.exists():
            try:
                data = json.loads(self.missed_file.read_text())
                return [MissedVuln.model_validate(m) for m in data]
            except (json.JSONDecodeError, Exception):
                return []
        return []

    def _save(self) -> None:
        data = [m.model_dump() for m in self.missed]
        self.missed_file.write_text(json.dumps(data, indent=2))

    def report(self, file: str, line: int, category: str, description: str, function: str = "") -> None:
        """Report a missed vulnerability."""
        missed = MissedVuln(
            file=file,
            line=line,
            function=function,
            category=category,
            description=description,
            reported_at=datetime.now(timezone.utc).isoformat() + "Z",
        )
        self.missed.append(missed)
        self._save()
        logger.info(f"Missed vulnerability reported: {category} in {file}:{line}")

    def diagnose(self, missed_vuln: MissedVuln, scored_functions: dict, hypotheses: dict, triage_results: dict, validation_results: dict) -> dict:
        """Run 5-step diagnosis on why a vulnerability was missed.

        Returns diagnosis dict with step results.
        """
        diagnosis = {}

        # Step 1: Was the function scored?
        func_key = f"{missed_vuln.file}::{missed_vuln.function}" if missed_vuln.function else missed_vuln.file
        scored = func_key in scored_functions
        diagnosis["step1_scored"] = {
            "passed": scored,
            "detail": f"Function {'was' if scored else 'was NOT'} scored. Score: {scored_functions.get(func_key, 'N/A')}",
        }

        # Step 2: Was a hypothesis generated?
        has_hypothesis = func_key in hypotheses
        diagnosis["step2_hypothesis"] = {
            "passed": has_hypothesis,
            "detail": f"Hypothesis {'was' if has_hypothesis else 'was NOT'} generated for category {missed_vuln.category}",
        }

        # Step 3: Was it filtered by confidence gate?
        filtered = func_key in hypotheses and hypotheses.get(func_key, {}).get("confidence", 1.0) < 0.4
        diagnosis["step3_filtered"] = {
            "passed": not filtered,
            "detail": "Hypothesis was filtered by confidence gate" if filtered else "Hypothesis passed confidence gate",
        }

        # Step 4: Was it triaged as false positive?
        triaged_fp = func_key in triage_results and triage_results.get(func_key) == "false_positive"
        diagnosis["step4_triaged_fp"] = {
            "passed": not triaged_fp,
            "detail": "Triaged as false positive" if triaged_fp else "Not classified as false positive",
        }

        # Step 5: Did the PoC fail?
        poc_failed = func_key in validation_results and not validation_results.get(func_key, {}).get("success", False)
        diagnosis["step5_poc_failed"] = {
            "passed": not poc_failed,
            "detail": "PoC validation failed" if poc_failed else "PoC not attempted or succeeded",
        }

        missed_vuln.diagnosis = diagnosis
        self._save()
        return diagnosis

    def get_pending(self) -> list[MissedVuln]:
        """Get missed vulns that haven't been diagnosed yet."""
        return [m for m in self.missed if m.diagnosis is None]
