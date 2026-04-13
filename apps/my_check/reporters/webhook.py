"""Webhook (Slack-compatible) reporter for my-check scan results."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckStatus, Report

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WebhookReporter:
    """POST scan results to a webhook URL (Slack-compatible payload)."""

    url: str | None = None

    async def emit(self, report: Report) -> None:
        if not self.url:
            logger.warning("WebhookReporter: no URL configured — skipping notification")
            return

        payload = self._build_payload(report)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(self.url, json=payload)
                resp.raise_for_status()
        except httpx.HTTPError:
            logger.warning("WebhookReporter: failed to POST to %s", self.url, exc_info=True)

    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(report: Report) -> dict:
        score = report.global_score
        s = report.summary

        summary_line = (
            f"Score: *{score:.0f}/100*\n"
            f"✓ {s[CheckStatus.PASS]} passed | "
            f"⚠ {s[CheckStatus.WARN]} warnings | "
            f"✗ {s[CheckStatus.FAIL]} failed"
        )

        detail_lines: list[str] = []
        for check_id, result in report.results.items():
            icon = {"pass": "✓", "warn": "⚠", "fail": "✗", "info": "ℹ"}[result.status.value]
            detail_lines.append(f"{icon} `{check_id}` — {result.message}")

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Security Scan: {report.target}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary_line},
            },
        ]

        if detail_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "\n".join(detail_lines)},
                }
            )

        if report.errors:
            error_text = "\n".join(f"⚠ `{cid}`: {err}" for cid, err in report.errors.items())
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Errors:*\n{error_text}"},
                }
            )

        return {
            "text": f"my-check scan results for {report.target}",
            "blocks": blocks,
        }
