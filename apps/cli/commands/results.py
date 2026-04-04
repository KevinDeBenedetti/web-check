"""Results command implementation."""

import builtins

import structlog
import typer
from cli.utils import APIClient, CLISettings, format_json, format_table
from rich.console import Console

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
        with console.status("[bold green]Fetching results..."):
            response = client.get("/api/scans")

        # API returns a list directly
        scans: builtins.list = response if isinstance(response, builtins.list) else []
        if status:
            scans = [s for s in scans if s.get("status") == status]
        scans = scans[:limit]

        if not scans:
            console.print("[yellow]No scan results found[/yellow]")
            return

        if output_format == "json":
            format_json(scans)
        else:
            display_data = [
                {
                    "ID": s.get("scan_id", "N/A"),
                    "Target": s.get("target", "N/A"),
                    "Status": s.get("status", "N/A"),
                    "Modules": len(s.get("results", [])),
                    "Started": s.get("started_at", "N/A")[:19] if s.get("started_at") else "N/A",
                }
                for s in scans
            ]
            format_table("Scan Results", display_data)

    except Exception as e:
        logger.error("fetch_results_failed", error=str(e))
        console.print(f"[red]✗ Failed to fetch results: {e}[/red]")
        raise typer.Exit(1) from None
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
            result = client.get(f"/api/scans/{scan_id}")

        if not result:
            console.print("[yellow]Scan result not found[/yellow]")
            raise typer.Exit(1) from None

        if output_format == "json":
            format_json(result)
        else:
            console.print("\n[bold cyan]Scan Details[/bold cyan]")
            console.print(f"ID:       {result.get('scan_id', 'N/A')}")
            console.print(f"Target:   {result.get('target', 'N/A')}")
            console.print(f"Status:   {result.get('status', 'N/A')}")
            console.print(f"Started:  {result.get('started_at', 'N/A')}")

            results = result.get("results", [])
            if results:
                console.print(f"\n[bold]Modules run ({len(results)})[/bold]")
                for r in results:
                    findings_n = len(r.get("findings", []))
                    icon = "✓" if r.get("status") == "success" else "✗"
                    console.print(
                        f"  [{icon}] {r.get('module', '?'):10} "
                        f"{r.get('duration_ms', 0)}ms  "
                        f"{findings_n} finding(s)"
                    )

    except Exception as e:
        logger.error("fetch_result_failed", scan_id=scan_id, error=str(e))
        console.print(f"[red]✗ Failed to fetch scan result: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


@results_app.command()
def clear(
    confirm: bool = typer.Option(False, "--confirm", help="Confirm deletion without prompt"),
) -> None:
    """Clear all scan results from the local database."""
    if not confirm:
        if not typer.confirm("Are you sure you want to delete all results?"):
            console.print("[yellow]Operation cancelled[/yellow]")
            return

    import subprocess

    try:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "web-check-api",
                "python3",
                "-c",
                "import sqlite3; db=sqlite3.connect('/app/data/web-check.db'); "
                "[db.execute(f'DELETE FROM {t}') for t in ('findings','scan_results','scans')]; "
                "db.commit(); print('cleared')",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            console.print("[green]✓ All results cleared[/green]")
        else:
            console.print(f"[red]✗ {result.stderr.strip()}[/red]")
            raise typer.Exit(1) from None
    except Exception as e:
        console.print(f"[red]✗ Failed to clear results: {e}[/red]")
        raise typer.Exit(1) from None
