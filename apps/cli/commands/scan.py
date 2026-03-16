"""Scan command implementation."""

from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.spinner import Spinner

from cli.utils import CLISettings, APIClient, format_findings, format_json, format_table

logger = structlog.get_logger()
console = Console()

scan_app = typer.Typer(help="Scan operations")


@scan_app.command()
def nuclei(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(300, help="Timeout in seconds (30-600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """Run Nuclei vulnerability scan.

    Fast vulnerability and CVE detection scan using Nuclei templates.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Running Nuclei scan..."):
            result = client.post(
                "/api/quick/nuclei",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
    except Exception as e:
        logger.error("nuclei_scan_failed", error=str(e))
        console.print(f"[red]✗ Nuclei scan failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@scan_app.command()
def nikto(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(600, help="Timeout in seconds (30-600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """Run Nikto web server scan.

    Comprehensive web server misconfiguration and vulnerability detection.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Running Nikto scan..."):
            result = client.post(
                "/api/quick/nikto",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
    except Exception as e:
        logger.error("nikto_scan_failed", error=str(e))
        console.print(f"[red]✗ Nikto scan failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@scan_app.command()
def quick(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(300, help="Timeout in seconds (30-600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """Run quick security scan.

    Runs fast scanning modules (Nuclei + DNS checks).
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Running quick scan..."):
            result = client.post(
                "/api/quick/scan",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
    except Exception as e:
        logger.error("quick_scan_failed", error=str(e))
        console.print(f"[red]✗ Quick scan failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


@scan_app.command()
def ssl(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(300, help="Timeout in seconds (30-600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """Run SSL/TLS security assessment.

    Comprehensive SSL/TLS configuration analysis using SSLyze.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status("[bold green]Running SSL scan..."):
            result = client.post(
                "/api/deep/ssl",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
    except Exception as e:
        logger.error("ssl_scan_failed", error=str(e))
        console.print(f"[red]✗ SSL scan failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        client.close()


def _display_result(result: dict, output_format: str) -> None:
    """Display scan result in requested format.

    Args:
        result: Scan result dictionary
        output_format: Format to display (table, json)
    """
    status = result.get("status", "unknown")
    module = result.get("module", "unknown")
    duration = result.get("duration_ms", 0)

    if output_format == "json":
        format_json(result)
    else:
        # Display summary
        status_icon = "✓" if status == "success" else "✗"
        console.print(
            f"\n[bold]{status_icon} Scan Result[/bold] ({module} - {duration}ms)\n"
        )

        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
        else:
            console.print(f"[green]Status: {status}[/green]")

            # Display findings
            if result.get("findings"):
                format_findings(result["findings"])

            # Display metadata
            if result.get("data"):
                console.print("\n[bold cyan]Metadata:[/bold cyan]")
                for key, value in result["data"].items():
                    console.print(f"  {key}: {value}")
