"""Rich terminal reporter for my-check scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from my_check.types import CheckCategory, CheckStatus, Report
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_STATUS_ICONS: dict[CheckStatus, tuple[str, str]] = {
    CheckStatus.PASS: ("✓", "green"),
    CheckStatus.WARN: ("⚠", "yellow"),
    CheckStatus.FAIL: ("✗", "red"),
    CheckStatus.INFO: ("ℹ", "blue"),
}

_CATEGORY_LABELS: dict[CheckCategory, str] = {
    CheckCategory.WEB: "Web",
    CheckCategory.K8S: "K8s",
}

_DETAIL_LIMIT = 15  # max issues shown inline before truncating


def _score_style(score: float) -> str:
    if score > 80:
        return "bold green"
    if score > 50:
        return "bold yellow"
    return "bold red"


def _normalize_issues(details: Any) -> list[dict[str, str]]:
    """Normalise the various shapes details can take into a flat list of dicts."""
    if isinstance(details, list):
        return [d for d in details if isinstance(d, dict)]
    if isinstance(details, dict):
        # e.g. secrets check: {"issues": [...], "external_secret_crds": bool}
        if "issues" in details and isinstance(details["issues"], list):
            return [d for d in details["issues"] if isinstance(d, dict)]
    return []


def _build_issue_table(issues: list[dict[str, str]], limit: int = _DETAIL_LIMIT) -> Table:
    """Build a compact Rich table for a list of issue dicts."""
    # Collect all keys that appear across issues (preserve insertion order)
    all_keys: list[str] = []
    seen: set[str] = set()
    for issue in issues[:limit]:
        for k in issue:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    tbl = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
    for k in all_keys:
        width = 40 if k in ("remediation", "reason", "message") else None
        tbl.add_column(k, style="dim" if k == "remediation" else None, max_width=width)

    for issue in issues[:limit]:
        tbl.add_row(*[issue.get(k, "") for k in all_keys])

    return tbl


@dataclass(slots=True)
class TerminalReporter:
    """Emit a rich terminal report for a completed scan."""

    console: Console = field(default_factory=Console)

    def emit(self, report: Report) -> None:
        self._print_header(report)
        self._print_categories(report)
        self._print_errors(report)
        self._print_summary(report)

    # ------------------------------------------------------------------

    def _print_header(self, report: Report) -> None:
        score = report.global_score
        style = _score_style(score)
        self.console.print()
        self.console.print(
            Text.assemble(
                ("my-check", "bold cyan"),
                " scan for ",
                (report.target, "bold"),
                "  —  Global Score: ",
                (f"{score:.1f}/100", style),
            )
        )
        self.console.print()

    def _print_categories(self, report: Report) -> None:
        by_cat = report.by_category
        for cat in CheckCategory:
            items = by_cat.get(cat)
            if not items:
                continue

            table = Table(
                title=f"{_CATEGORY_LABELS[cat]} Checks",
                title_style="bold",
                show_lines=True,
            )
            table.add_column("Check ID", style="cyan", min_width=20)
            table.add_column("Status", justify="center", min_width=8)
            table.add_column("Score", justify="right", min_width=6)
            table.add_column("Message")

            for check_id, result in items:
                icon, color = _STATUS_ICONS[result.status]
                table.add_row(
                    check_id,
                    Text(f"{icon} {result.status.value}", style=color),
                    Text(str(result.score), style=_score_style(result.score)),
                    result.message,
                )

            self.console.print(table)
            self.console.print()

            # Print detail panels for failed / warn checks
            for check_id, result in items:
                if result.status not in (CheckStatus.FAIL, CheckStatus.WARN):
                    continue
                if not result.details:
                    continue
                self._print_detail_panel(check_id, result)

    def _print_detail_panel(self, check_id: str, result: Any) -> None:
        issues = _normalize_issues(result.details)
        if not issues:
            return

        icon, color = _STATUS_ICONS[result.status]
        title = Text.assemble(
            (f"{icon} ", color),
            (check_id, f"bold {color}"),
            (" — Details", "bold"),
        )

        shown = issues[:_DETAIL_LIMIT]
        hidden = len(issues) - len(shown)

        content: list[Any] = [_build_issue_table(shown)]

        if hidden > 0:
            content.append(Text(f"\n  … and {hidden} more issue(s).", style="dim italic"))

        if result.remediation:
            content.append(Text(f"\n  💡 {result.remediation}", style="yellow"))

        # Stack content in a simple vertical group
        from rich.console import Group

        self.console.print(Panel(Group(*content), title=title, border_style=color, expand=False))
        self.console.print()

    def _print_errors(self, report: Report) -> None:
        if not report.errors:
            return
        table = Table(title="Errors", title_style="bold red", show_lines=True)
        table.add_column("Check ID", style="cyan")
        table.add_column("Error", style="red")
        for check_id, error in report.errors.items():
            table.add_row(check_id, error)
        self.console.print(table)
        self.console.print()

    def _print_summary(self, report: Report) -> None:
        s = report.summary
        parts = [
            f"[green]✓ {s[CheckStatus.PASS]} passed[/green]",
            f"[yellow]⚠ {s[CheckStatus.WARN]} warnings[/yellow]",
            f"[red]✗ {s[CheckStatus.FAIL]} failed[/red]",
            f"[blue]ℹ {s[CheckStatus.INFO]} info[/blue]",
        ]
        self.console.print(" | ".join(parts))
        self.console.print()
