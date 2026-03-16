"""Web-Check CLI main application."""

import sys

import structlog
import typer
from rich.console import Console

from cli import __version__
from cli.commands import config_app, results_app, scan_app
from cli.utils import CLISettings

logger = structlog.get_logger()
console = Console()

app = typer.Typer(
    help="Web-Check Security Scanner CLI",
    pretty_exceptions_enable=False,
)

# Register subcommands
app.add_typer(scan_app, name="scan", help="Scan operations")
app.add_typer(results_app, name="results", help="Results operations")
app.add_typer(config_app, name="config", help="Configuration operations")


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=lambda x: _show_version(x) if x else None,
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug mode"),
) -> None:
    """Web-Check Security Scanner - Self-hosted vulnerability detection tool."""
    if debug:
        structlog.configure(
            processors=[
                structlog.processors.JSONRenderer(),
            ]
        )


def _show_version(value: bool) -> None:
    """Display version and exit."""
    if value:
        console.print(f"Web-Check CLI v{__version__}")
        raise typer.Exit()


@app.command()
def health() -> None:
    """Check API health status."""
    settings = CLISettings()
    try:
        import httpx

        with httpx.Client(timeout=5) as client:
            response = client.get(f"{settings.api_url}/api/health")
            response.raise_for_status()
            health = response.json()

        status = health.get("status", "unknown")
        status_color = "green" if status == "healthy" else "yellow"
        console.print(f"[{status_color}]API Status: {status}[/{status_color}]")

    except Exception as e:
        console.print(f"[red]✗ API unreachable: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
