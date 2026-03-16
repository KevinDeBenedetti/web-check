"""Results command implementation."""

import structlog
import typer
from rich.console import Console

from cli.utils import CLISettings, APIClient, format_table, format_json

logger = structlog.get_logger()
console = Console()

results_app = typer.Typer(help="Results operations")


@results_app.command()
def list(
    limit: int = typer.Option(10, help="Number of results to return"),
    status: str = typer.Option(None, help="Filter by status (success, error, timeout)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """List recent scan results."""
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        params = {"limit": limit}
        if status:
            params["status"] = status

        with console.status("[bold green]Fetching results..."):
            response = client.get("/api/scans", **params)

        results = response.get("data", [])

        if not results:
            console.print("[yellow]No scan results found[/yellow]")
            return

        if output_format == "json":
            format_json(results)
        else:
            # Format for table display
            display_data = []
            for result in results:
                display_data.append({
                    "ID": result.get("id", "N/A")[:8],
                    "Module": result.get("module", "N/A"),
                    "Target": result.get("target", "N/A"),
                    "Status": result.get("status", "N/A"),
                    "Findings": len(result.get("findings", [])),
                    "Duration (ms)": result.get("duration_ms", 0),
                })

            format_table("Scan Results", display_data)

    except Exception as e:
        logger.error("fetch_results_failed", error=str(e))
        console.print(f"[red]✗ Failed to fetch results: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@results_app.command()
def show(
    scan_id: str = typer.Argument(..., help="Scan ID to display"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """Display details of a specific scan result."""
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Fetching scan result..."):
            response = client.get(f"/api/scans/{scan_id}")

        result = response.get("data")

        if not result:
            console.print("[yellow]Scan result not found[/yellow]")
            raise typer.Exit(1)

        if output_format == "json":
            format_json(result)
        else:
            # Display detailed result
            console.print(f"\n[bold cyan]Scan Details[/bold cyan]")
            console.print(f"ID: {result.get('id', 'N/A')}")
            console.print(f"Module: {result.get('module', 'N/A')}")
            console.print(f"Target: {result.get('target', 'N/A')}")
            console.print(f"Status: {result.get('status', 'N/A')}")
            console.print(f"Duration: {result.get('duration_ms', 0)}ms")
            console.print(f"Timestamp: {result.get('timestamp', 'N/A')}")

            if result.get("error"):
                console.print(f"\n[red]Error: {result['error']}[/red]")

            if result.get("findings"):
                console.print(f"\n[bold]Findings ({len(result['findings'])})[/bold]")
                for i, finding in enumerate(result["findings"], 1):
                    severity = finding.get("severity", "unknown").upper()
                    console.print(f"  [{i}] {finding.get('title', 'N/A')} ({severity})")

    except Exception as e:
        logger.error("fetch_result_failed", scan_id=scan_id, error=str(e))
        console.print(f"[red]✗ Failed to fetch scan result: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@results_app.command()
def clear(
    confirm: bool = typer.Option(
        False, "--confirm", help="Confirm deletion without prompt"
    ),
) -> None:
    """Clear all scan results."""
    if not confirm:
        result = typer.confirm("Are you sure you want to delete all results?")
        if not result:
            console.print("[yellow]Operation cancelled[/yellow]")
            return

    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Clearing results..."):
            response = client.post("/api/scans/clear")

        console.print("[green]✓ All results cleared[/green]")
    except Exception as e:
        logger.error("clear_results_failed", error=str(e))
        console.print(f"[red]✗ Failed to clear results: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()
