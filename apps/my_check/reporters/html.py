"""Self-contained HTML reporter for my-check scan results."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path

from my_check.types import CheckCategory, CheckStatus, Report
from rich.console import Console

_STATUS_COLORS: dict[CheckStatus, str] = {
    CheckStatus.PASS: "#16a34a",
    CheckStatus.WARN: "#ca8a04",
    CheckStatus.FAIL: "#dc2626",
    CheckStatus.INFO: "#2563eb",
}

_STATUS_ICONS: dict[CheckStatus, str] = {
    CheckStatus.PASS: "✓",
    CheckStatus.WARN: "⚠",
    CheckStatus.FAIL: "✗",
    CheckStatus.INFO: "ℹ",
}

_CATEGORY_LABELS: dict[CheckCategory, str] = {
    CheckCategory.WEB: "Web Checks",
    CheckCategory.K8S: "Kubernetes Checks",
}


def _score_color(score: float) -> str:
    if score > 80:
        return "#16a34a"
    if score > 50:
        return "#ca8a04"
    return "#dc2626"


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


@dataclass(slots=True)
class HtmlReporter:
    """Generate a self-contained HTML report."""

    output_dir: Path
    previous_report: str | None = None

    def emit(self, report: Report) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        console = Console(stderr=True)

        diff_html = self._build_diff(report) if self.previous_report else ""
        body = self._render(report, diff_html)

        path = self.output_dir / "my-check-report.html"
        path.write_text(body, encoding="utf-8")
        console.print(f"[green]HTML report written to[/green] {path}")

    # ------------------------------------------------------------------
    # Diff against previous report
    # ------------------------------------------------------------------

    def _build_diff(self, report: Report) -> str:
        if not self.previous_report:
            return ""
        try:
            prev = json.loads(Path(self.previous_report).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "<p class='note'>Could not load previous report for comparison.</p>"

        prev_results: dict[str, dict] = prev.get("results", {})
        prev_score = prev.get("global_score", 0)
        cur_score = report.global_score
        delta = cur_score - prev_score

        rows: list[str] = []
        all_ids = sorted(set(report.results) | set(prev_results))
        for cid in all_ids:
            cur = report.results.get(cid)
            prv = prev_results.get(cid)
            if cur and not prv:
                rows.append(
                    f"<tr><td>{_esc(cid)}</td><td>—</td><td>{cur.score}</td><td>New check</td></tr>"
                )
            elif prv and not cur:
                rows.append(
                    f"<tr><td>{_esc(cid)}</td><td>{prv.get('score', '?')}</td>"
                    "<td>—</td><td>Removed</td></tr>"
                )
            elif cur and prv:
                old_score = prv.get("score", 0)
                if cur.score != old_score:
                    change = cur.score - old_score
                    sign = "+" if change > 0 else ""
                    rows.append(
                        f"<tr><td>{_esc(cid)}</td><td>{old_score}</td>"
                        f"<td>{cur.score}</td><td>{sign}{change}</td></tr>"
                    )

        if not rows:
            return ""

        sign = "+" if delta > 0 else ""
        return (
            "<section class='diff'>"
            f"<h2>Comparison with Previous Report</h2>"
            f"<p>Global score change: <strong>{sign}{delta:.1f}</strong></p>"
            "<table><thead><tr><th>Check</th><th>Previous</th>"
            "<th>Current</th><th>Change</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></section>"
        )

    # ------------------------------------------------------------------
    # Full HTML render
    # ------------------------------------------------------------------

    def _render(self, report: Report, diff_html: str) -> str:
        score = report.global_score
        score_col = _score_color(score)
        summary = report.summary

        summary_cards = "".join(
            f"<div class='card' style='border-top:4px solid {_STATUS_COLORS[s]}'>"
            f"<span class='icon' style='color:{_STATUS_COLORS[s]}'>{_STATUS_ICONS[s]}</span>"
            f"<span class='count'>{c}</span>"
            f"<span class='label'>{s.value}</span></div>"
            for s, c in summary.items()
        )

        category_sections = self._render_categories(report)
        error_section = self._render_errors(report)

        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>my-check report — {_esc(report.target)}</title>
<style>
  :root {{ --bg:#f8fafc; --fg:#0f172a; --card:#fff; --border:#e2e8f0; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:system-ui,-apple-system,sans-serif; background:var(--bg);
          color:var(--fg); padding:2rem; max-width:960px; margin:auto; }}
  h1 {{ font-size:1.5rem; margin-bottom:.25rem; }}
  .target {{ color:#64748b; font-size:.95rem; margin-bottom:1.5rem; }}
  .score {{ font-size:2.5rem; font-weight:700; color:{score_col};
            margin-bottom:1.5rem; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:.5rem;
           padding:1rem 1.5rem; text-align:center; min-width:120px; flex:1; }}
  .card .icon {{ font-size:1.4rem; display:block; }}
  .card .count {{ font-size:1.8rem; font-weight:700; display:block; }}
  .card .label {{ font-size:.8rem; text-transform:uppercase; color:#64748b; }}
  h2 {{ margin:1.5rem 0 .75rem; font-size:1.2rem; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:1.5rem;
           background:var(--card); border-radius:.5rem; overflow:hidden;
           border:1px solid var(--border); }}
  th,td {{ padding:.6rem .8rem; text-align:left; border-bottom:1px solid var(--border); }}
  th {{ background:#f1f5f9; font-size:.85rem; text-transform:uppercase; color:#475569; }}
  .status {{ font-weight:600; }}
  .remediation {{ font-size:.85rem; color:#64748b; margin-top:.25rem; }}
  .note {{ color:#64748b; font-style:italic; }}
  .diff {{ margin-bottom:2rem; }}
  .errors td {{ color:#dc2626; }}
  footer {{ margin-top:3rem; color:#94a3b8; font-size:.8rem; text-align:center; }}
</style>
</head>
<body>
  <h1>my-check Security Report</h1>
  <p class="target">{_esc(report.target)}</p>
  <div class="score">{score:.1f} / 100</div>
  <div class="cards">{summary_cards}</div>
  {diff_html}
  {category_sections}
  {error_section}
  <footer>Generated by my-check</footer>
</body>
</html>
"""

    def _render_categories(self, report: Report) -> str:
        parts: list[str] = []
        by_cat = report.by_category
        for cat in CheckCategory:
            items = by_cat.get(cat)
            if not items:
                continue
            rows = ""
            for check_id, result in items:
                color = _STATUS_COLORS[result.status]
                icon = _STATUS_ICONS[result.status]
                remediation = ""
                if result.status == CheckStatus.FAIL and result.remediation:
                    remediation = f"<div class='remediation'>💡 {_esc(result.remediation)}</div>"
                rows += (
                    f"<tr><td>{_esc(check_id)}</td>"
                    f"<td class='status' style='color:{color}'>{icon} {result.status.value}</td>"
                    f"<td>{result.score}</td>"
                    f"<td>{_esc(result.message)}{remediation}</td></tr>"
                )
            parts.append(
                f"<section><h2>{_CATEGORY_LABELS[cat]}</h2>"
                "<table><thead><tr><th>Check</th><th>Status</th>"
                f"<th>Score</th><th>Message</th></tr></thead><tbody>{rows}</tbody></table>"
                "</section>"
            )
        return "\n".join(parts)

    def _render_errors(self, report: Report) -> str:
        if not report.errors:
            return ""
        rows = "".join(
            f"<tr><td>{_esc(cid)}</td><td>{_esc(err)}</td></tr>"
            for cid, err in report.errors.items()
        )
        return (
            "<section><h2>Errors</h2>"
            "<table class='errors'><thead><tr><th>Check</th><th>Error</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>"
        )
