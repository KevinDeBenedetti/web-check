"""Check command — complete security assessment workflow for a website."""

import structlog
import typer
from cli.report import save_report
from cli.utils import APIClient, CLISettings, format_json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = structlog.get_logger()
console = Console()

check_app = typer.Typer(help="Run a complete security check workflow")

_CHECK_STEPS = [
    ("dns",         "DNS & Reachability",         "/api/quick/dns",      None),
    ("dns_enum",    "DNS Record Enumeration",      "/api/quick/dns-enum", None),
    ("headers",     "HTTP Security Headers",       "/api/quick/headers",  None),
    ("ssl",         "SSL/TLS Assessment",          "/api/deep/sslyze",    300),
    ("nuclei",      "Vulnerability Scan (Nuclei)", "/api/quick/nuclei",   300),
    ("nikto",       "Web Server Scan (Nikto)",     "/api/quick/nikto",    600),
]

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "cyan",
}


def _domain_to_url(domain: str) -> str:
    """Ensure domain has a scheme."""
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"


def _pick_domain(domain: str | None) -> str:
    """Resolve the target domain — use argument, .env list, or prompt."""
    if domain:
        return _domain_to_url(domain)

    settings = CLISettings()
    domains = settings.domains

    if domains:
        from rich.prompt import Prompt

        console.print("\n[bold]Configured domains:[/bold]")
        for i, d in enumerate(domains, 1):
            console.print(f"  [cyan]{i}.[/cyan] {d}")
        console.print()

        choice = Prompt.ask(
            "[bold]Select a domain (number or custom URL)[/bold]",
            default="1",
        )

        if choice.isdigit() and 1 <= int(choice) <= len(domains):
            return _domain_to_url(domains[int(choice) - 1])
        return _domain_to_url(choice)

    from rich.prompt import Prompt

    url = Prompt.ask("[bold]Target URL[/bold]", default="https://example.com")
    return _domain_to_url(url)


@check_app.callback(invoke_without_command=True)
def check(
    ctx: typer.Context,
    domain: str = typer.Argument(None, help="Target domain or URL (default: pick from .env)"),
    skip: str = typer.Option("", help="Comma-separated steps to skip (dns,ssl,nuclei,nikto)"),
    output_format: str = typer.Option("table", help="Output format (table, json)"),
    report: bool = typer.Option(False, "--report", help="Save a Markdown report to outputs/"),
) -> None:
    """Run a complete security assessment: DNS → SSL → Nuclei → Nikto.

    Without arguments, offers to pick from ALLOWED_DOMAINS in .env.
    """
    if ctx.invoked_subcommand is not None:
        return

    url = _pick_domain(domain)
    skip_set = {s.strip().lower() for s in skip.split(",") if s.strip()}
    run_check(url, skip_set=skip_set, output_format=output_format, save_report=report)


def run_check(url: str, *, skip_set: set[str] | None = None, output_format: str = "table", save_report: bool = False) -> None:
    """Execute the complete security check workflow.

    Args:
        url: Target URL (must include scheme).
        skip_set: Step keys to skip (dns, ssl, nuclei, nikto).
        output_format: Output format (table, json).
        save_report: Save a Markdown report to outputs/.
    """
    skip_set = skip_set or set()
    steps = [(key, label, ep, to) for key, label, ep, to in _CHECK_STEPS if key not in skip_set]

    if not steps:
        console.print("[yellow]All steps skipped — nothing to do.[/yellow]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold cyan]🔒 Security Check: {url}[/bold cyan]")
    console.print(f"   Steps: [cyan]{' → '.join(label for _, label, _, _ in steps)}[/cyan]\n")

    settings = CLISettings()
    client = APIClient(settings.api_url, settings.api_timeout)
    step_results: list[dict] = []

    try:
        for key, label, endpoint, timeout in steps:
            with console.status(f"[bold green]Running {label}…"):
                try:
                    params: dict = {"url": url}
                    if timeout:
                        params["timeout"] = timeout
                    result = client.get(endpoint, **params)
                    result["_step"] = key
                    result["_label"] = label
                    step_results.append(result)

                    status = result.get("status", "unknown")
                    duration = result.get("duration_ms", 0)
                    findings_n = len(result.get("findings", []))
                    error_msg = result.get("error")

                    if status == "success":
                        icon, color = "✓", "green"
                    elif status == "timeout":
                        icon, color = "⏱", "yellow"
                    else:
                        icon, color = "✗", "red"

                    line = Text()
                    line.append(f"  {icon} ", style=color)
                    line.append(f"{label}", style="bold")
                    line.append(f"  {_format_duration(duration)}", style="dim")

                    # Inline metadata highlights per step
                    hints = _step_hints(key, result)
                    if hints:
                        line.append(f"  {hints}", style="dim cyan")

                    if findings_n:
                        line.append(f"  {findings_n} finding(s)", style="yellow")

                    if error_msg and status != "success":
                        line.append(f"  ({error_msg})", style="dim red")

                    console.print(line)
                except Exception as e:
                    console.print(f"  [red]✗ {label}: {e}[/red]")
                    step_results.append(
                        {"_step": key, "_label": label, "status": "error", "error": str(e)}
                    )

        # Display consolidated report
        console.print()

        if output_format == "json":
            format_json(
                {
                    "target": url,
                    "steps": [
                        {k: v for k, v in r.items() if not k.startswith("_")} for r in step_results
                    ],
                }
            )
            return

        _display_check_report(url, step_results)

        if save_report:
            _save_markdown_report(url, step_results)

    except Exception as e:
        logger.error("check_failed", error=str(e))
        console.print(f"[red]✗ Check failed: {e}[/red]")
        raise typer.Exit(1) from None
    finally:
        client.close()


def _format_duration(ms: int) -> str:
    """Format duration in human-friendly way."""
    if ms < 1000:
        return f"{ms}ms"
    secs = ms / 1000
    if secs < 60:
        return f"{secs:.1f}s"
    mins = int(secs // 60)
    remaining = secs % 60
    return f"{mins}m{remaining:.0f}s"


def _step_hints(key: str, result: dict) -> str:
    """Return short inline metadata string for a completed step."""
    data = result.get("data") or {}
    status = result.get("status", "")
    parts: list[str] = []

    if key == "dns":
        if data.get("resolvable") is True:
            http_code = data.get("http_status")
            parts.append(f"HTTP {http_code}" if http_code else "resolvable")
        elif data.get("resolvable") is False:
            parts.append("unresolvable")
    elif key == "dns_enum":
        record_types = list((data.get("records") or {}).keys())
        if record_types:
            parts.append(f"{len(record_types)} record type(s)")
        spf = data.get("spf")
        if spf:
            parts.append("SPF ✓")
        dmarc = data.get("dmarc")
        if dmarc:
            parts.append("DMARC ✓")
    elif key == "headers":
        missing = data.get("headers_missing") or []
        present = data.get("headers_present") or []
        if present:
            parts.append(f"{len(present)} header(s) present")
        if missing:
            parts.append(f"{len(missing)} missing")
    elif key == "ssl":
        if status == "success":
            host = data.get("hostname", "")
            port = data.get("port", 443)
            parts.append(f"{host}:{port}")
    elif key == "nuclei":
        matched = data.get("templates_matched", 0)
        if matched:
            parts.append(f"{matched} template(s) matched")
    elif key == "nikto":
        count = data.get("findings_count", 0)
        if count:
            parts.append(f"{count} issue(s) detected")

    return " · ".join(parts)


def _display_check_report(url: str, step_results: list[dict]) -> None:
    """Print consolidated security check report with detailed step info."""
    # ── Summary table ──
    summary = Table(title=f"Security Check — {url}", show_header=True, header_style="bold magenta")
    summary.add_column("Step", style="cyan", min_width=28)
    summary.add_column("Status")
    summary.add_column("Duration", justify="right")
    summary.add_column("Findings", justify="right")
    summary.add_column("Details", style="dim")

    all_findings: list[dict] = []
    for r in step_results:
        status = r.get("status", "?")
        color = {"success": "green", "timeout": "yellow"}.get(status, "red")
        findings = r.get("findings", [])
        all_findings.extend({**f, "_step": r["_label"]} for f in findings)

        detail = _step_hints(r.get("_step", ""), r) or (r.get("error", "") if status != "success" else "")

        summary.add_row(
            r.get("_label", "?"),
            f"[{color}]{status}[/{color}]",
            _format_duration(r.get("duration_ms", 0)),
            f"[yellow]{len(findings)}[/yellow]" if findings else "0",
            detail[:60],
        )

    console.print(summary)

    # ── Per-step metadata panels ──
    for r in step_results:
        key = r.get("_step", "")
        label = r.get("_label", "")
        data = r.get("data") or {}
        status = r.get("status", "unknown")
        error_msg = r.get("error")

        if key == "dns" and data:
            lines = [
                f"  Domain:     {data.get('domain', 'N/A')}",
                f"  Resolvable: {data.get('resolvable', 'N/A')}",
                f"  HTTP Code:  {data.get('http_status', 'N/A')}",
            ]
            console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

        elif key == "dns_enum" and data:
            rec = data.get("records") or {}
            lines = [f"  Domain:     {data.get('domain', 'N/A')}"]
            for rtype, vals in rec.items():
                lines.append(f"  {rtype}:{'':>6}{', '.join(vals[:2])}{'…' if len(vals) > 2 else ''}")
            spf = data.get("spf")
            dmarc = data.get("dmarc")
            dkim = data.get("dkim_found")
            lines += [
                f"  SPF:        {'✓ present' if spf else '✗ missing'}",
                f"  DMARC:      {'✓ present' if dmarc else '✗ missing'}",
                f"  DKIM:       {'✓ found' if dkim else '✗ not found'}",
            ]
            console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

        elif key == "headers" and data:
            missing = data.get("headers_missing") or []
            present = data.get("headers_present") or []
            lines = [
                f"  Present headers:  {len(present)}",
                f"  Missing headers:  {len(missing)}",
            ]
            if missing:
                lines.append(f"  Missing:  {', '.join(missing[:4])}{'…' if len(missing) > 4 else ''}")
            srv = data.get("server")
            if srv:
                lines.append(f"  Server:   {srv}")
            console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

        elif key == "ssl":
            lines = []
            if status == "success":
                lines.append(f"  Hostname: {data.get('hostname', 'N/A')}")
                lines.append(f"  Port:     {data.get('port', 443)}")
                n = len(r.get("findings", []))
                lines.append(f"  Issues:   {n} protocol/cipher finding(s)")
            elif error_msg:
                lines.append(f"  Error: {error_msg}")
            if lines:
                console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

        elif key == "nuclei":
            lines = []
            if status == "success":
                matched = data.get("templates_matched", 0)
                lines.append(f"  Templates matched: {matched}")
                lines.append(f"  Duration:          {_format_duration(r.get('duration_ms', 0))}")
            elif error_msg:
                lines.append(f"  Error: {error_msg}")
            if lines:
                console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

        elif key == "nikto":
            lines = []
            if status == "success":
                count = data.get("findings_count", 0)
                lines.append(f"  Issues detected: {count}")
                lines.append(f"  Duration:        {_format_duration(r.get('duration_ms', 0))}")
            elif error_msg:
                lines.append(f"  Error: {error_msg}")
            if lines:
                console.print(Panel("\n".join(lines), title=f"[cyan]{label}[/cyan]", border_style="dim", expand=False))

    # ── Detailed findings ──
    if all_findings:
        console.print(
            f"\n[bold red]⚠  {len(all_findings)} Finding(s) across all steps[/bold red]\n"
        )
        _display_findings_table(all_findings)
    else:
        console.print("\n[bold green]✓ No security findings detected[/bold green]")

    # ── Error / warning summary ──
    error_count = sum(1 for r in step_results if r.get("status") == "error")
    timeout_count = sum(1 for r in step_results if r.get("status") == "timeout")
    if error_count or timeout_count:
        parts = []
        if error_count:
            parts.append(f"{error_count} errored")
        if timeout_count:
            parts.append(f"{timeout_count} timed out")
        console.print(f"\n[yellow]⚠  {', '.join(parts)} — results may be incomplete[/yellow]")


def _display_findings_table(findings: list[dict]) -> None:
    """Render findings as a Rich table with severity colors."""
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Step", style="cyan", width=16)
    table.add_column("Title", min_width=30)
    table.add_column("CVE", width=16)
    table.add_column("CVSS", justify="right", width=5)

    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "unknown").upper()
        color = _SEVERITY_COLORS.get(sev, "white")
        cve = f.get("cve") or ""
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else ""

        table.add_row(
            str(i),
            f"[{color}]{sev}[/{color}]",
            f.get("_step", ""),
            f.get("title", "N/A"),
            cve,
            cvss,
        )

    console.print(table)

    # Print full descriptions for non-info findings
    has_detail = False
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if not has_detail:
                console.print("\n[bold]Finding Details[/bold]")
                has_detail = True
            color = _SEVERITY_COLORS.get(sev, "white")
            console.print(f"\n  [{color}][{i}] {sev}[/{color}] — {f.get('title', 'N/A')}")
            desc = f.get("description", "")
            if desc:
                console.print(f"      {desc}")
            ref = f.get("reference", "")
            if ref:
                console.print(f"      [dim]Ref: {ref}[/dim]")


def _save_markdown_report(url: str, step_results: list[dict]) -> None:
    """Delegate to shared report module."""
    save_report(url, step_results, scan_type="check")


