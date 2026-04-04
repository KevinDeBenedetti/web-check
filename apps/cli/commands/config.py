"""Configuration command implementation."""

import structlog
import typer
from cli.utils import CLISettings
from rich.console import Console
from rich.table import Table

logger = structlog.get_logger()
console = Console()

config_app = typer.Typer(help="Configuration operations")


@config_app.command()
def show() -> None:
    """Display current CLI configuration."""
    settings = CLISettings()

    table = Table(title="Web-Check CLI Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("API URL", settings.api_url)
    table.add_row("API Timeout", f"{settings.api_timeout}s")
    table.add_row("Output Format", settings.output_format)
    table.add_row("Debug", "Yes" if settings.debug else "No")
    table.add_row("Log Level", settings.log_level)

    console.print(table)
    console.print("\n[dim]Environment Variables:[/dim]")
    console.print("  WEB_CHECK_CLI_API_URL")
    console.print("  WEB_CHECK_CLI_API_TIMEOUT")
    console.print("  WEB_CHECK_CLI_OUTPUT_FORMAT")
    console.print("  WEB_CHECK_CLI_DEBUG")
    console.print("  WEB_CHECK_CLI_LOG_LEVEL")


@config_app.command()
def validate() -> None:
    """Validate API connection."""
    settings = CLISettings()
    console.print(f"[cyan]Testing connection to {settings.api_url}...[/cyan]")

    try:
        import httpx

        with httpx.Client(timeout=5) as client:
            response = client.get(f"{settings.api_url}/api/health")
            response.raise_for_status()

        console.print("[green]✓ API connection successful[/green]")
        health_data = response.json()
        console.print(f"  Status: {health_data.get('status', 'unknown')}")

    except Exception as e:
        logger.error("api_connection_failed", api_url=settings.api_url, error=str(e))
        console.print(f"[red]✗ API connection failed: {e}[/red]")
        raise typer.Exit(1) from None
