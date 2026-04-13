"""Scheduler: discover, run, and aggregate checks in parallel."""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from my_check.types import (
    Check,
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
    Report,
)
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

_STATUS_ICONS: dict[CheckStatus, tuple[str, str]] = {
    CheckStatus.PASS: ("✅", "green"),
    CheckStatus.WARN: ("⚠️", "yellow"),
    CheckStatus.FAIL: ("❌", "red"),
    CheckStatus.INFO: ("ℹ️", "blue"),
}


def _run_check_in_thread(check: Check, arg: str | K8sContext) -> CheckResult:
    """Run a check in a worker thread with its own event loop."""
    return asyncio.run(check.run(arg))


@dataclass(slots=True)
class Scheduler:
    """Collects checks, runs them in parallel, and builds a Report."""

    checks: list[Check] = field(default_factory=list)
    timeout: float = 60.0

    def register(self, check: Check) -> None:
        self.checks.append(check)

    def register_many(self, checks: list[Check]) -> None:
        self.checks.extend(checks)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run(
        self,
        *,
        target: str | None = None,
        k8s_ctx: K8sContext | None = None,
        enabled_ids: set[str] | None = None,
        category: CheckCategory | None = None,
    ) -> Report:
        """Run all matching checks concurrently in threads and return a Report."""
        report_target = target or (k8s_ctx.context_name if k8s_ctx else "unknown")
        report = Report(target=report_target or "unknown")

        selected = self._select(enabled_ids, category)
        if not selected:
            logger.warning("No checks selected to run")
            return report

        # Live progress state per check
        progress: dict[str, tuple[str, str]] = {c.id: ("⏳ running…", "dim") for c in selected}
        console = Console()

        def _build_table() -> Table:
            tbl = Table(box=None, show_header=False, padding=(0, 2))
            tbl.add_column("Check", style="cyan", min_width=24)
            tbl.add_column("Status")
            for cid in [c.id for c in selected]:
                msg, style = progress[cid]
                tbl.add_row(cid, Text(msg, style=style))
            return tbl

        tasks = [
            self._run_one(check, target=target, k8s_ctx=k8s_ctx, progress=progress)
            for check in selected
        ]

        with Live(_build_table(), console=console, refresh_per_second=4) as live:
            gather = asyncio.gather(*tasks, return_exceptions=True)
            while not gather.done():
                live.update(_build_table())
                await asyncio.sleep(0.25)
            results = await gather
            live.update(_build_table())

        for check, result in zip(selected, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("Check %s raised: %s", check.id, result)
                report.errors[check.id] = str(result)
            else:
                report.results[check.id] = result

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select(
        self,
        enabled_ids: set[str] | None,
        category: CheckCategory | None,
    ) -> list[Check]:
        selected: list[Check] = []
        for c in self.checks:
            if category and c.category != category:
                continue
            if enabled_ids and c.id not in enabled_ids:
                continue
            selected.append(c)
        return selected

    async def _run_one(
        self,
        check: Check,
        *,
        target: str | None,
        k8s_ctx: K8sContext | None,
        progress: dict[str, tuple[str, str]],
    ) -> CheckResult:
        arg: str | K8sContext
        if check.category == CheckCategory.K8S:
            if k8s_ctx is None:
                progress[check.id] = ("⏭ skipped", "dim")
                return CheckResult(
                    status=CheckStatus.INFO,
                    score=0,
                    message="Skipped — no Kubernetes context provided",
                )
            arg = k8s_ctx
        else:
            if target is None:
                progress[check.id] = ("⏭ skipped", "dim")
                return CheckResult(
                    status=CheckStatus.INFO,
                    score=0,
                    message="Skipped — no target URL provided",
                )
            arg = target

        start = time.monotonic()
        loop = asyncio.get_running_loop()

        try:
            # Each check runs in its own thread+event loop so blocking k8s
            # client calls never stall the main event loop or each other.
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = await asyncio.wait_for(
                    loop.run_in_executor(pool, _run_check_in_thread, check, arg),
                    timeout=self.timeout,
                )
        except TimeoutError:
            elapsed = time.monotonic() - start
            progress[check.id] = (f"⏱ timed out ({elapsed:.0f}s)", "red")
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Timed out after {elapsed:.1f}s",
            )
        except Exception as exc:
            logger.exception("Check %s failed", check.id)
            progress[check.id] = ("💥 error", "red")
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Error: {exc}",
            )
        else:
            elapsed = time.monotonic() - start
            icon, style = _STATUS_ICONS[result.status]
            progress[check.id] = (f"{icon} {result.status.value}  ({elapsed:.1f}s)", style)
            logger.info("Check %s completed in %.2fs — %s", check.id, elapsed, result.status)
            return result
