"""Scan state persistence and resume logic."""
from __future__ import annotations

import logging
from pathlib import Path

from argus.models.scan import ScanState

logger = logging.getLogger(__name__)

class ScanStateManager:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def save_state(self, scan_id: str, state: ScanState) -> None:
        """Persist scan state for resume."""
        state_file = self.state_dir / f"{scan_id}.json"
        state_file.write_text(state.model_dump_json(indent=2))

    def load_state(self, scan_id: str | None = None) -> ScanState | None:
        """Load persisted scan state. If no scan_id, load the most recent."""
        if scan_id:
            state_file = self.state_dir / f"{scan_id}.json"
            if state_file.exists():
                return ScanState.model_validate_json(state_file.read_text())
            return None

        # Find most recent state file
        state_files = sorted(self.state_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if state_files:
            return ScanState.model_validate_json(state_files[0].read_text())
        return None

    def clean_state(self, scan_id: str | None = None) -> None:
        """Remove persisted scan state."""
        if scan_id:
            state_file = self.state_dir / f"{scan_id}.json"
            if state_file.exists():
                state_file.unlink()
        else:
            for f in self.state_dir.glob("*.json"):
                f.unlink()

    def list_states(self) -> list[str]:
        """List all persisted scan IDs."""
        return [f.stem for f in self.state_dir.glob("*.json")]
