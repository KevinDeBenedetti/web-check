"""Scan command implementation."""

import time
from typing import Any

import structlog
import typer
from cli.report import normalise_full_scan, normalise_single, save_report
from cli.utils import APIClient, CLISettings, format_findings, format_json
from rich.console import Console
from rich.table import Table
from rich.text import Text

logger = structlog.get_logger()
console = Console()

scan_app = typer.Typer(help="Scan operations")

# The modules and profiles /api/scans/start accepts come from GET /api/catalog.


def _profile_modules(catalog: dict[str, Any], profile_id: str) -> list[str] | None:
    """Modules of a catalog profile; None when the catalog has no such profile."""
    profiles = {p["id"]: p.get("modules", []) for p in catalog.get("profiles", [])}
    modules = profiles.get(profile_id)
    return list(modules) if modules is not None else None


@scan_app.command()
def nuclei(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(300, help="Timeout in seconds (30-3600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run Nuclei vulnerability scan.

    Fast vulnerability and CVE detection scan using Nuclei templates.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout, settings.api_key)

    try:
        with console.status("[bold green]Running Nuclei scan..."):
            result = client.get(
                "/api/quick/nuclei",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
        if report:
            save_report(url, normalise_single(result), scan_type="nuclei")
    except Exception as e:
        logger.error("nuclei_scan_failed", error=str(e))
        console.print(f"[red]✗ Nuclei scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


@scan_app.command()
def nikto(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(600, help="Timeout in seconds (30-3600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run Nikto web server scan.

    Comprehensive web server misconfiguration and vulnerability detection.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout, settings.api_key)

    try:
        with console.status("[bold green]Running Nikto scan..."):
            result = client.get(
                "/api/quick/nikto",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
        if report:
            save_report(url, normalise_single(result), scan_type="nikto")
    except Exception as e:
        logger.error("nikto_scan_failed", error=str(e))
        console.print(f"[red]✗ Nikto scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


@scan_app.command()
def quick(
    url: str = typer.Argument(..., help="Target URL to scan"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run quick DNS + reachability check."""
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout, settings.api_key)

    try:
        with console.status("[bold green]Running quick scan..."):
            result = client.get("/api/quick/dns", url=url)

        _display_result(result, output_format)
        if report:
            save_report(url, normalise_single(result), scan_type="quick")
    except Exception as e:
        logger.error("quick_scan_failed", error=str(e))
        console.print(f"[red]✗ Quick scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


@scan_app.command()
def ssl(
    url: str = typer.Argument(..., help="Target URL to scan"),
    timeout: int = typer.Option(300, help="Timeout in seconds (60-3600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run SSL/TLS security assessment.

    Comprehensive SSL/TLS configuration analysis using SSLyze.
    """
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout, settings.api_key)

    try:
        with console.status("[bold green]Running SSL scan..."):
            result = client.get(
                "/api/deep/sslyze",
                url=url,
                timeout=timeout,
            )

        _display_result(result, output_format)
        if report:
            save_report(url, normalise_single(result), scan_type="ssl")
    except Exception as e:
        logger.error("ssl_scan_failed", error=str(e))
        console.print(f"[red]✗ SSL scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


@scan_app.command()
def full(
    url: str = typer.Argument(..., help="Target URL to scan"),
    modules: str | None = typer.Option(
        None,
        help="Comma-separated modules, as listed by the API catalog (GET /api/catalog)",
    ),
    profile: str | None = typer.Option(
        None,
        help="Profile of the API catalog to run (default: the catalog's default profile)",
    ),
    all_modules: bool = typer.Option(False, "--all", help="Run every module of the API catalog"),
    timeout: int = typer.Option(300, help="Timeout per module in seconds (30-3600)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run a complete multi-module security scan (async, with live progress).

    Default: the API catalog's default profile, the same scan as the web UI.
    --profile picks another profile, --modules lists the modules, and --all runs
    every module of the catalog (much slower).
    """
    # JSON mode: stdout carries the JSON document only; progress goes to stderr.
    out = Console(stderr=True) if output_format == "json" else console

    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout, settings.api_key)

    try:
        try:
            catalog = client.get("/api/catalog")
        except Exception as e:
            out.print(f"[red]✗ Could not read the module catalog (GET /api/catalog): {e}[/red]")
            raise typer.Exit(1) from None
        available = [module["id"] for module in catalog.get("modules", [])]
        if not available:
            out.print("[red]✗ The API catalog lists no scan module[/red]")
            raise typer.Exit(1) from None
        if profile is not None and (modules is not None or all_modules):
            out.print("[red]✗ Use --profile, --modules or --all, not several[/red]")
            raise typer.Exit(1) from None
        profile_id: str | None = None
        if all_modules:
            module_list = available
        elif modules is not None:
            module_list = [m.strip() for m in modules.split(",") if m.strip()]
        else:
            profile_id = profile or catalog.get("default_profile")
            if not profile_id:
                out.print("[red]✗ The API catalog has no default profile: pass --profile[/red]")
                raise typer.Exit(1) from None
            selected = _profile_modules(catalog, profile_id)
            if selected is None:
                profile_ids = [p["id"] for p in catalog.get("profiles", [])]
                out.print(f"[red]✗ Unknown profile: {profile_id}[/red]")
                out.print(f"  Available: {', '.join(profile_ids) or 'none'}")
                raise typer.Exit(1) from None
            if not selected:
                out.print(f"[red]✗ The profile {profile_id} lists no module[/red]")
                raise typer.Exit(1) from None
            module_list = selected

        invalid = [m for m in module_list if m not in available]
        if invalid:
            out.print(f"[red]✗ Unknown module(s): {', '.join(invalid)}[/red]")
            out.print(f"  Available: {', '.join(available)}")
            raise typer.Exit(1) from None

        # Start async scan
        out.print(f"\n[bold cyan]🔍 Starting full scan on {url}[/bold cyan]")
        if profile_id:
            out.print(f"   Profile : [cyan]{profile_id}[/cyan]")
        out.print(f"   Modules : [cyan]{', '.join(module_list)}[/cyan]")
        out.print(f"   Timeout : {timeout}s per module\n")

        response = client.post(
            "/api/scans/start",
            json={"target": url, "modules": module_list, "timeout": timeout},
        )
        scan_id = response.get("scan_id")
        if not scan_id:
            out.print("[red]✗ Failed to start scan — no scan_id returned[/red]")
            raise typer.Exit(1) from None

        out.print(f"[dim]Scan ID: {scan_id}[/dim]\n")

        # Poll until complete
        poll_interval = 5
        max_wait = timeout * len(module_list) + 60
        elapsed = 0
        last_count = 0

        with out.status("[bold green]Scanning…") as status:
            while elapsed < max_wait:
                time.sleep(poll_interval)
                elapsed += poll_interval

                scan = client.get(f"/api/scans/{scan_id}")
                current_status = scan.get("status", "running")
                results = scan.get("results", [])

                if len(results) > last_count:
                    for r in results[last_count:]:
                        icon = "✓" if r.get("status") == "success" else "✗"
                        findings_n = len(r.get("findings", []))
                        color = "green" if r.get("status") == "success" else "yellow"
                        status.update(
                            f"[{color}][{icon}] {r.get('module', '?'):10}  "
                            f"{r.get('duration_ms', 0)}ms  "
                            f"{findings_n} finding(s)[/{color}]"
                        )
                        out.log(
                            f"[{color}][{icon}][/{color}] [bold]{r.get('module', '?')}[/bold]  "
                            f"[dim]{r.get('duration_ms', 0)}ms[/dim]  "
                            f"[yellow]{findings_n} finding(s)[/yellow]"
                        )
                    last_count = len(results)

                if current_status != "running":
                    break

        # Final results
        scan = client.get(f"/api/scans/{scan_id}")
        results = scan.get("results", [])

        if output_format == "json":
            if report:
                save_report(url, normalise_full_scan(scan), scan_type="full")
            format_json(scan)
            return

        console.print()
        _display_full_summary(scan_id, url, results)

        if report:
            save_report(url, normalise_full_scan(scan), scan_type="full")

    except typer.Exit:
        raise
    except Exception as e:
        logger.error("full_scan_failed", error=str(e))
        out.print(f"[red]✗ Full scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


def _display_full_summary(scan_id: str, url: str, results: list) -> None:
    """Print a consolidated findings table for a full scan."""
    all_findings = []
    for r in results:
        for f in r.get("findings", []):
            all_findings.append({**f, "_module": r.get("module", "?")})

    # Module summary table
    summary = Table(title=f"Full Scan — {url}", show_header=True, header_style="bold magenta")
    summary.add_column("Module", style="cyan")
    summary.add_column("Status")
    summary.add_column("Duration", justify="right")
    summary.add_column("Findings", justify="right")

    for r in results:
        status = r.get("status", "?")
        color = "green" if status == "success" else "red"
        findings_n = len(r.get("findings", []))
        summary.add_row(
            r.get("module", "?"),
            f"[{color}]{status}[/{color}]",
            f"{r.get('duration_ms', 0)}ms",
            f"[yellow]{findings_n}[/yellow]" if findings_n else "0",
        )

    console.print(summary)

    if all_findings:
        console.print(
            f"\n[bold red]⚠  {len(all_findings)} Finding(s) across all modules[/bold red]\n"
        )
        format_findings(all_findings)
    else:
        console.print("\n[bold green]✓ No security findings detected[/bold green]")

    console.print(
        f"\n[dim]Scan ID: {scan_id} — run 'web-check results show {scan_id}' to review later[/dim]"
    )


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
        console.print(f"\n[bold]{status_icon} Scan Result[/bold] ({module} - {duration}ms)\n")

        if result.get("error"):
            console.print(Text(f"Error: {result['error']}", style="red"))
        else:
            console.print(f"[green]Status: {status}[/green]")

            # Display findings
            if result.get("findings"):
                format_findings(result["findings"])

            # Display metadata
            if result.get("data"):
                console.print("\n[bold cyan]Metadata:[/bold cyan]")
                for key, value in result["data"].items():
                    console.print(Text(f"  {key}: {value}"))
