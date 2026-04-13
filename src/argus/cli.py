"""Click CLI for Argus."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from dotenv import load_dotenv

from argus.config import load_config
from argus.output.formatter import format_report

load_dotenv()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(verbose: bool = False):
    """Argus: Autonomous vulnerability discovery and exploit validation."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--categories", "-c", default=None, help="Comma-separated categories to scan")
@click.option(
    "--format", "-f", "output_format", default="markdown",
    type=click.Choice(["text", "json", "sarif", "ai", "markdown"]),
)
@click.option("--output", "-o", "output_file", default="report.md", type=click.Path(), help="Write report to file")
@click.option("--no-cache", is_flag=True, help="Ignore cached results")
@click.option("--resume", is_flag=True, help="Resume interrupted scan")
@click.option("--iterations", type=int, default=None, help="Override max iteration budget")
@click.option("--fix", is_flag=True, help="Generate patches for confirmed findings")
def scan(path, categories, output_format, output_file, no_cache, resume, iterations, fix):
    """Run a vulnerability scan on a codebase."""
    project_root = Path(path).resolve()
    config = load_config(project_root)

    if no_cache:
        config.cache.enabled = False
    if iterations:
        config.validation.max_iterations_simple = iterations
        config.validation.max_iterations_medium = iterations
    if fix:
        config.triage.patch = True

    cat_list = categories.split(",") if categories else None

    from argus.llm.sampling import create_llm_client
    from argus.pipeline.orchestrator import ScanOrchestrator
    from argus.sandbox.manager import DockerSandboxManager

    llm_client = create_llm_client(config)
    sandbox = DockerSandboxManager(config.sandbox)
    orchestrator = ScanOrchestrator(project_root, llm_client, sandbox, config)

    report = asyncio.run(orchestrator.run(resume=resume, categories=cat_list))
    result = format_report(report, output_format)
    if output_file:
        Path(output_file).write_text(result)
        click.echo(f"Report written to {output_file}")
    else:
        click.echo(result)


@main.command()
@click.argument("finding_id")
@click.option("--reason", "-r", required=True, help="Reason for suppression")
@click.option(
    "--scope", "-s", default="finding",
    type=click.Choice(["finding", "function", "rule", "project"]),
)
def suppress(finding_id, reason, scope):
    """Suppress a false positive finding."""
    from argus.suppression.manager import SuppressionManager
    manager = SuppressionManager(Path("."))
    manager.suppress(finding_id, reason, scope)
    click.echo(f"Suppressed {finding_id} (scope: {scope})")


@main.command()
@click.argument("location")  # file:line format
@click.option("--category", "-c", required=True, help="Vulnerability category")
@click.option("--description", "-d", required=True, help="Description of the missed vuln")
def missed(location, category, description):
    """Report a vulnerability that Argus missed."""
    parts = location.rsplit(":", 1)
    file_path = parts[0]
    line = int(parts[1]) if len(parts) > 1 else 0

    from argus.suppression.missed import MissedVulnManager
    manager = MissedVulnManager(Path("."))
    manager.report(file_path, line, category, description)
    click.echo(f"Missed vulnerability reported: {category} in {location}")


@main.command()
def status():
    """Check scan progress."""
    from argus.pipeline.resume import ScanStateManager
    manager = ScanStateManager(Path(".argus/scan-state"))
    states = manager.list_states()
    if not states:
        click.echo("No scan state found.")
        return
    for sid in states:
        state = manager.load_state(sid)
        if state:
            p = state.progress
            click.echo(f"Scan {sid}: {p.status.value} ({p.targets_scanned}/{p.targets_total} targets)")


@main.command()
@click.option("--severity", "-s", default=None, help="Filter by severity")
@click.option("--category", "-c", default=None, help="Filter by category")
def findings(severity, category):
    """List findings from the last scan."""
    # Try to load from most recent report cache
    cache_file = Path(".argus/cache/last_report.json")
    if not cache_file.exists():
        click.echo("No findings available. Run 'argus scan' first.")
        return

    from argus.models.output import Report
    report = Report.model_validate_json(cache_file.read_text())

    filtered = report.findings
    if severity:
        sevs = set(severity.split(","))
        filtered = [f for f in filtered if f.severity.value in sevs]
    if category:
        cats = set(category.split(","))
        filtered = [f for f in filtered if f.category.value in cats]

    if not filtered:
        click.echo("No findings match the filters.")
        return

    for f in filtered:
        click.echo(f"[{f.severity.value.upper()}] {f.finding_id}: {f.title}")




@main.command("clean-state")
def clean_state():
    """Remove persisted scan state."""
    from argus.pipeline.resume import ScanStateManager
    manager = ScanStateManager(Path(".argus/scan-state"))
    manager.clean_state()
    click.echo("Scan state cleaned.")


if __name__ == "__main__":
    main()
