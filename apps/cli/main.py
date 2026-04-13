"""Web-Check CLI main application."""

import structlog
import typer
from cli import __version__
from cli.commands import check_app, config_app, domains_app, results_app, scan_app
from cli.commands.check import _pick_domain
from cli.commands.scan import _display_result
from cli.utils import APIClient, CLISettings
from rich.console import Console
from rich.prompt import Prompt
from rich.rule import Rule

logger = structlog.get_logger()
console = Console()

app = typer.Typer(
    help="Web-Check Security Scanner CLI",
    pretty_exceptions_enable=False,
    invoke_without_command=True,
)

# Register subcommands
app.add_typer(check_app, name="check", help="Complete security check workflow")
app.add_typer(scan_app, name="scan", help="Scan operations")
app.add_typer(results_app, name="results", help="Results operations")
app.add_typer(config_app, name="config", help="Configuration operations")
app.add_typer(domains_app, name="domains", help="Manage allowed domains")


@app.callback()
def main(
    ctx: typer.Context,
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
    # No subcommand given → launch interactive guide
    if ctx.invoked_subcommand is None:
        guide()


def _show_version(value: bool) -> None:
    """Display version and exit."""
    if value:
        console.print(f"Web-Check CLI v{__version__}")
        raise typer.Exit()


_SCAN_DESCRIPTIONS = {
    "full": "Complete scan — nuclei + nikto + zap (async, with live progress)",
    "quick": "DNS + reachability check (fast)",
    "ssl": "SSL/TLS configuration analysis",
    "nuclei": "Nuclei CVE & vulnerability templates",
    "nikto": "Web server misconfiguration scan",
}

_SCAN_ENDPOINTS = {
    "quick": "/api/quick/dns",
    "ssl": "/api/deep/sslyze",
    "nuclei": "/api/quick/nuclei",
    "nikto": "/api/quick/nikto",
}


@app.command()
def guide() -> None:
    """Interactive guided wizard — choose a scan or check health."""
    console.print()
    console.print(Rule("[bold cyan]🔒  Web-Check Security Scanner[/bold cyan]"))
    console.print()

    # ── Step 1: top-level action ──────────────────────────────────────────
    action = Prompt.ask(
        "[bold]What would you like to do?[/bold]",
        choices=["check", "scan", "health", "quit"],
        default="check",
    )

    if action == "quit":
        console.print("[dim]Bye![/dim]")
        raise typer.Exit()

    if action == "health":
        _run_health()
        return

    if action == "check":
        console.print("\n[dim]Running complete security check (DNS → SSL → Nuclei → Nikto)[/dim]")
        url = _pick_domain(None)
        fmt = Prompt.ask(
            "[bold]Output format[/bold]",
            choices=["table", "json"],
            default="table",
        )
        save = Prompt.ask(
            "[bold]Save Markdown report?[/bold]",
            choices=["yes", "no"],
            default="yes",
        )
        from cli.commands.check import run_check

        run_check(url, skip_set=set(), output_format=fmt, save_report=(save == "yes"))
        return

    # ── Step 2: scan type ─────────────────────────────────────────────────
    console.print()
    for name, desc in _SCAN_DESCRIPTIONS.items():
        console.print(f"  [cyan]{name:<8}[/cyan] {desc}")
    console.print()

    scan_type = Prompt.ask(
        "[bold]Select scan type[/bold]",
        choices=list(_SCAN_DESCRIPTIONS),
        default="full",
    )

    # ── Step 3: target URL ────────────────────────────────────────────────
    url = _pick_domain(None)

    # ── Step 4: output format ─────────────────────────────────────────────
    fmt = Prompt.ask(
        "[bold]Output format[/bold]",
        choices=["table", "json"],
        default="table",
    )

    # ── Step 5: save report ───────────────────────────────────────────────
    save = Prompt.ask(
        "[bold]Save Markdown report?[/bold]",
        choices=["yes", "no"],
        default="yes",
    )
    do_report = save == "yes"

    # ── Execute ───────────────────────────────────────────────────────────
    console.print()

    # Full scan delegates to the `scan full` command logic
    if scan_type == "full":
        import time

        from cli.commands.scan import _DEFAULT_MODULES, _display_full_summary
        from cli.report import normalise_full_scan, save_report

        settings = CLISettings()
        client = APIClient(settings.api_url, settings.api_timeout)
        try:
            console.print(f"[bold cyan]🔍 Starting full scan on {url}[/bold cyan]")
            console.print(f"   Modules : [cyan]{', '.join(_DEFAULT_MODULES)}[/cyan]\n")

            response = client.post(
                "/api/scans/start",
                json={"target": url, "modules": _DEFAULT_MODULES, "timeout": 300},
            )
            scan_id = response.get("scan_id")
            if not scan_id:
                console.print("[red]✗ Failed to start scan[/red]")
                raise typer.Exit(1)

            last_count = 0
            with console.status("[bold green]Scanning…") as status:
                for _ in range(300):
                    time.sleep(5)
                    scan = client.get(f"/api/scans/{scan_id}")
                    results = scan.get("results", [])
                    if len(results) > last_count:
                        for r in results[last_count:]:
                            icon = "✓" if r.get("status") == "success" else "✗"
                            color = "green" if r.get("status") == "success" else "yellow"
                            findings_n = len(r.get("findings", []))
                            console.log(
                                f"[{color}][{icon}][/{color}] [bold]{r.get('module', '?')}[/bold]  "
                                f"[dim]{r.get('duration_ms', 0)}ms[/dim]  "
                                f"[yellow]{findings_n} finding(s)[/yellow]"
                            )
                            status.update(f"[green]Completed {len(results)} module(s)…[/green]")
                        last_count = len(results)
                    if scan.get("status") != "running":
                        break

            scan = client.get(f"/api/scans/{scan_id}")
            if fmt == "json":
                _display_result(scan, "json")
            else:
                _display_full_summary(scan_id, url, scan.get("results", []))
            if do_report:
                save_report(url, normalise_full_scan(scan), scan_type="full")
        except Exception as e:
            console.print(f"[red]✗ Scan failed: {e}[/red]")
            raise typer.Exit(1) from None
        finally:
            client.close()
        return

    endpoint = _SCAN_ENDPOINTS[scan_type]
    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)

    try:
        with console.status(f"[bold green]Running {scan_type} scan on {url}…"):
            result = client.get(endpoint, url=url)
        _display_result(result, fmt)
        if do_report:
            from cli.report import normalise_single, save_report
            save_report(url, normalise_single(result), scan_type=scan_type)
    except Exception as e:
        console.print(f"[red]✗ Scan failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


def _run_health() -> None:
    """Health check helper (shared by guide and health command)."""
    settings = CLISettings()
    try:
        import httpx

        with httpx.Client(timeout=5) as client:
            response = client.get(f"{settings.api_url}/api/health")
            response.raise_for_status()
            health_data = response.json()

        status = health_data.get("status", "unknown")
        color = "green" if status == "healthy" else "yellow"
        console.print(f"[{color}]● API Status: {status}[/{color}]")
    except Exception as e:
        console.print(f"[red]✗ API unreachable: {e}[/red]")
        raise typer.Exit(1) from None


@app.command()
def health() -> None:
    """Check API health status."""
    _run_health()


if __name__ == "__main__":
    app()
