"""HTTP client utilities for API communication."""

import json
from typing import Any

import httpx
import structlog
from rich.console import Console
from rich.table import Table

logger = structlog.get_logger()
console = Console()


class APIClient:
    """HTTP client for API communication."""

    def __init__(self, base_url: str, timeout: int = 600):
        """Initialize API client.

        Args:
            base_url: Base URL of the API
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)

    def post(self, endpoint: str, **params: Any) -> dict[str, Any]:
        """Make POST request to API.

        Args:
            endpoint: API endpoint path
            **params: Query or body parameters

        Returns:
            Response JSON
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.client.post(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error("api_request_failed", url=url, error=str(e))
            console.print(f"[red]Error: {e}[/red]")
            raise

    def get(self, endpoint: str, **params: Any) -> dict[str, Any]:
        """Make GET request to API.

        Args:
            endpoint: API endpoint path
            **params: Query parameters

        Returns:
            Response JSON
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.client.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error("api_request_failed", url=url, error=str(e))
            console.print(f"[red]Error: {e}[/red]")
            raise

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self) -> "APIClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


def format_table(title: str, data: list[dict[str, Any]]) -> None:
    """Format and print data as a table.

    Args:
        title: Table title
        data: List of dictionaries to display
    """
    if not data:
        console.print("[yellow]No data to display[/yellow]")
        return

    table = Table(title=title, show_header=True, header_style="bold magenta")

    # Add columns from first row
    keys = list(data[0].keys())
    for key in keys:
        table.add_column(key, style="cyan")

    # Add rows
    for row in data:
        values = [str(row.get(key, "")) for key in keys]
        table.add_row(*values)

    console.print(table)


def format_json(data: Any) -> None:
    """Format and print data as JSON.

    Args:
        data: Data to display
    """
    console.print_json(data=data)


def format_findings(findings: list[dict[str, Any]]) -> None:
    """Format and print security findings.

    Args:
        findings: List of findings
    """
    if not findings:
        console.print("[green]✓ No security findings detected[/green]")
        return

    console.print(f"\n[bold red]Found {len(findings)} Finding(s)[/bold red]\n")

    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "unknown").upper()
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan",
        }.get(severity, "white")

        console.print(f"[{severity_color}][{i}] {severity}[/{severity_color}]")
        console.print(f"  Title: {finding.get('title', 'N/A')}")
        console.print(f"  Description: {finding.get('description', 'N/A')}")

        if finding.get("cve"):
            console.print(f"  CVE: {finding['cve']}")
        if finding.get("cvss_score") is not None:
            console.print(f"  CVSS: {finding['cvss_score']}")
        if finding.get("reference"):
            console.print(f"  Reference: {finding['reference']}")

        console.print()
