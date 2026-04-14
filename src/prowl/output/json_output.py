"""JSON output format."""
from __future__ import annotations

from prowl.models.output import Report


def render_json(report: Report) -> str:
    """Render report as JSON."""
    return report.model_dump_json(indent=2)
