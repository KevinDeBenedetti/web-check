"""JSON and SARIF reporter for my-check scan results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from my_check.types import CheckStatus, Report
from rich.console import Console

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_STATUS_TO_SARIF_LEVEL: dict[CheckStatus, str] = {
    CheckStatus.FAIL: "error",
    CheckStatus.WARN: "warning",
    CheckStatus.INFO: "note",
    CheckStatus.PASS: "note",
}


@dataclass(slots=True)
class JsonReporter:
    """Write scan results as JSON and optionally SARIF."""

    output_dir: Path
    sarif: bool = False

    def emit(self, report: Report) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        console = Console(stderr=True)

        self._write_json(report, console)
        if self.sarif:
            self._write_sarif(report, console)

    # ------------------------------------------------------------------

    def _write_json(self, report: Report, console: Console) -> None:
        payload = {
            "target": report.target,
            "global_score": round(report.global_score, 2),
            "summary": {s.value: c for s, c in report.summary.items()},
            "results": {check_id: asdict(result) for check_id, result in report.results.items()},
            "errors": report.errors,
        }
        path = self.output_dir / "my-check-results.json"
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        console.print(f"[green]JSON report written to[/green] {path}")

    def _write_sarif(self, report: Report, console: Console) -> None:
        rules: list[dict] = []
        results: list[dict] = []

        for idx, (check_id, result) in enumerate(report.results.items()):
            rules.append(
                {
                    "id": check_id,
                    "shortDescription": {"text": result.message},
                    **(
                        {"helpUri": result.remediation}
                        if result.remediation and result.remediation.startswith("http")
                        else {}
                    ),
                    **(
                        {"help": {"text": result.remediation}}
                        if result.remediation and not result.remediation.startswith("http")
                        else {}
                    ),
                }
            )
            results.append(
                {
                    "ruleId": check_id,
                    "ruleIndex": idx,
                    "level": _STATUS_TO_SARIF_LEVEL[result.status],
                    "message": {"text": result.message},
                    "properties": {
                        "score": result.score,
                    },
                }
            )

        sarif_doc = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "my-check",
                            "version": "0.1.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        path = self.output_dir / "my-check-results.sarif"
        path.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]SARIF report written to[/green] {path}")
