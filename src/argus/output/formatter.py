"""Output format dispatch."""
from __future__ import annotations

from argus.models.output import Report


def format_report(report: Report, output_format: str = "markdown") -> str:
    """Format a scan report in the requested format."""
    formatters = {
        "text": _format_text,
        "json": _format_json,
        "sarif": _format_sarif,
        "ai": _format_ai,
        "markdown": _format_markdown,
    }
    formatter = formatters.get(output_format, _format_markdown)
    return formatter(report)


def _format_text(report: Report) -> str:
    from argus.output.text import render_text
    return render_text(report)


def _format_json(report: Report) -> str:
    from argus.output.json_output import render_json
    return render_json(report)


def _format_sarif(report: Report) -> str:
    from argus.output.sarif import render_sarif
    return render_sarif(report)


def _format_ai(report: Report) -> str:
    from argus.output.ai_output import render_ai
    return render_ai(report)


def _format_markdown(report: Report) -> str:
    from argus.output.markdown import render_markdown
    return render_markdown(report)
