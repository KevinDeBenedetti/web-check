"""Domains command implementation — list and manage allowed scan targets."""

import typer
from cli.utils import CLISettings, format_json
from rich.console import Console
from rich.table import Table

console = Console()

domains_app = typer.Typer(help="Manage allowed scan domains")


@domains_app.command("list")
def list_domains(
    output_format: str = typer.Option("table", help="Output format (table, json)"),
) -> None:
    """List domains configured in ALLOWED_DOMAINS (.env)."""
    settings = CLISettings()
    domains = settings.domains

    if not domains:
        console.print("[yellow]No domains configured.[/yellow]")
        console.print("[dim]Set ALLOWED_DOMAINS in your .env file (comma-separated).[/dim]")
        raise typer.Exit(1)

    if output_format == "json":
        format_json(domains)
        return

    table = Table(title="Allowed Domains", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Domain", style="cyan")
    table.add_column("URL", style="green")

    for i, domain in enumerate(domains, 1):
        table.add_row(str(i), domain, f"https://{domain}")

    console.print(table)
    console.print(f"\n[dim]Source: ALLOWED_DOMAINS in .env ({len(domains)} domain(s))[/dim]")
