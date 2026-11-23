"""HTTP client utilities for API communication."""

from typing import Any

import httpx
import structlog
from rich.console import Console
from rich.table import Table
from rich.text import Text

logger = structlog.get_logger()
console = Console()


class APIClient:
    """HTTP client for API communication."""

    def __init__(self, base_url: str, timeout: int = 600, api_key: str | None = None):
        """Initialize API client.

        Args:
            base_url: Base URL of the API
            timeout: Request timeout in seconds
            api_key: Value for the X-API-Key header (when the API requires one)
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        headers = {"X-API-Key": api_key} if api_key else None
        self.client = httpx.Client(timeout=timeout, follow_redirects=True, headers=headers)

    def _timeout_for(self, params: dict[str, Any]) -> float:
        """Client deadline: never shorter than the scan timeout sent to the API."""
        scan_timeout = params.get("timeout")
        if isinstance(scan_timeout, int | float):
            return max(self.timeout, scan_timeout + 30)
        return self.timeout

    def post(self, endpoint: str, json: dict | None = None, **params: Any) -> dict[str, Any]:
        """Make POST request to API.

        Args:
            endpoint: API endpoint path
            json: Optional JSON body
            **params: Query parameters

        Returns:
            Response JSON
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.client.post(url, json=json, params=params if params else None)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error("api_request_failed", url=url, error=str(e))
            console.print(f"[red]Error: {e}[/red]")
            raise

    def get(self, endpoint: str, **params: Any) -> Any:
        """Make GET request to API.

        Args:
            endpoint: API endpoint path
            **params: Query parameters

        Returns:
            Response JSON (dict or list depending on endpoint)
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.client.get(url, params=params, timeout=self._timeout_for(params))
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
        values = [Text(str(row.get(key, ""))) for key in keys]
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

        console.print(Text(f"[{i}] {severity}", style=severity_color))
        console.print(Text(f"  Title: {finding.get('title', 'N/A')}"))
        console.print(Text(f"  Description: {finding.get('description', 'N/A')}"))

        if finding.get("cve"):
            console.print(Text(f"  CVE: {finding['cve']}"))
        if finding.get("cvss_score") is not None:
            console.print(Text(f"  CVSS: {finding['cvss_score']}"))
        if finding.get("reference"):
            console.print(Text(f"  Reference: {finding['reference']}"))

        console.print()
