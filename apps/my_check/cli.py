"""my-check CLI — unified web & Kubernetes security scanner."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from my_check.config import K8sConfig, MyCheckConfig, load_config
from my_check.registry import get_all_checks, get_k8s_checks, get_web_checks
from my_check.scheduler import Scheduler
from my_check.types import CheckCategory, K8sContext, Report
from rich.console import Console

app = typer.Typer(
    name="my-check",
    help="Unified web & Kubernetes security scanner.",
    invoke_without_command=True,  # allows the callback to launch wizard when no sub-command
    rich_markup_mode="rich",
)
console = Console()

# ---------------------------------------------------------------------------
# Callback — launch interactive wizard when called with no sub-command
# ---------------------------------------------------------------------------


@app.callback()
def _main(ctx: typer.Context) -> None:
    """Run the interactive wizard when invoked with no sub-command."""
    if ctx.invoked_subcommand is None:
        from my_check.wizard import run_wizard

        run_wizard()


# ---------------------------------------------------------------------------
# Shared option types
# ---------------------------------------------------------------------------

OptOutput = Annotated[
    str,
    typer.Option(
        "--output",
        "-o",
        help="Comma-separated reporters: terminal,json,html,webhook",
    ),
]
OptConfig = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to my-check.config.json"),
]
OptContext = Annotated[
    str | None,
    typer.Option("--context", help="Kubeconfig context name"),
]
OptKubeconfig = Annotated[
    str | None,
    typer.Option("--kubeconfig", help="Path to kubeconfig file"),
]
OptNamespace = Annotated[
    str | None,
    typer.Option("--namespace", "-n", help="Kubernetes namespace to scope checks"),
]
OptVerbose = Annotated[
    bool,
    typer.Option("--verbose", "-v", help="Enable verbose logging"),
]
OptStrict = Annotated[
    bool,
    typer.Option("--strict", help="Exit with code 1 when any check fails (useful for CI)"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _build_k8s_context(
    cfg: K8sConfig,
    context: str | None,
    kubeconfig: str | None,
    namespace: str | None,
) -> K8sContext:
    return K8sContext(
        context_name=context or cfg.context,
        kubeconfig_path=kubeconfig or cfg.kubeconfig,
        namespace=namespace or cfg.namespace,
    )


async def _emit_reports(report: Report, cfg: MyCheckConfig) -> None:
    output_dir = Path(cfg.output.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt in cfg.output.formats:
        match fmt:
            case "terminal":
                from my_check.reporters.terminal import TerminalReporter

                TerminalReporter(console=console).emit(report)
            case "json":
                from my_check.reporters.json_reporter import JsonReporter

                JsonReporter(output_dir=output_dir, sarif=cfg.output.sarif).emit(report)
            case "markdown":
                from my_check.reporters.markdown_reporter import MarkdownReporter

                MarkdownReporter(output_dir=output_dir).emit(report)
            case "html":
                from my_check.reporters.html import HtmlReporter

                HtmlReporter(
                    output_dir=output_dir,
                    previous_report=cfg.output.previous_report,
                ).emit(report)
            case "webhook":
                from my_check.reporters.webhook import WebhookReporter

                await WebhookReporter(url=cfg.output.webhook_url).emit(report)
            case _:
                console.print(f"[yellow]Unknown reporter: {fmt}[/yellow]")


def _run(report: Report, cfg: MyCheckConfig, *, strict: bool = False) -> None:
    asyncio.run(_emit_reports(report, cfg))
    fail_count = report.summary.get("fail", 0)  # type: ignore[arg-type]
    raise typer.Exit(code=1 if strict and fail_count > 0 else 0)


# ---------------------------------------------------------------------------
# Commands (non-interactive, for scripting / CI)
# ---------------------------------------------------------------------------


@app.command()
def web(
    url: Annotated[str, typer.Argument(help="Target URL to scan")],
    output: OptOutput = "terminal",
    config: OptConfig = None,
    verbose: OptVerbose = False,
    strict: OptStrict = False,
) -> None:
    """Run web security checks against a URL."""
    _setup_logging(verbose)
    cfg = load_config(config)
    cfg.output.formats = [f.strip() for f in output.split(",")]

    checks = get_web_checks()
    scheduler = Scheduler(checks=checks, timeout=cfg.web.timeout)
    enabled = set(cfg.web.enabled_checks)
    report = asyncio.run(scheduler.run(target=url, enabled_ids=enabled, category=CheckCategory.WEB))
    _run(report, cfg, strict=strict)


@app.command()
def k8s(
    context: OptContext = None,
    kubeconfig: OptKubeconfig = None,
    namespace: OptNamespace = None,
    output: OptOutput = "terminal",
    config: OptConfig = None,
    verbose: OptVerbose = False,
    strict: OptStrict = False,
) -> None:
    """Run Kubernetes security checks."""
    _setup_logging(verbose)
    cfg = load_config(config)
    cfg.output.formats = [f.strip() for f in output.split(",")]

    k8s_ctx = _build_k8s_context(cfg.k8s, context, kubeconfig, namespace)
    checks = get_k8s_checks()
    scheduler = Scheduler(checks=checks, timeout=cfg.k8s.timeout)
    enabled = set(cfg.k8s.enabled_checks)
    report = asyncio.run(
        scheduler.run(k8s_ctx=k8s_ctx, enabled_ids=enabled, category=CheckCategory.K8S)
    )
    _run(report, cfg, strict=strict)


@app.command(name="all")
def all_checks(
    url: Annotated[str, typer.Argument(help="Target URL to scan")],
    context: OptContext = None,
    kubeconfig: OptKubeconfig = None,
    namespace: OptNamespace = None,
    output: OptOutput = "terminal",
    config: OptConfig = None,
    verbose: OptVerbose = False,
    strict: OptStrict = False,
) -> None:
    """Run all web and Kubernetes security checks."""
    _setup_logging(verbose)
    cfg = load_config(config)
    cfg.output.formats = [f.strip() for f in output.split(",")]

    k8s_ctx = _build_k8s_context(cfg.k8s, context, kubeconfig, namespace)
    checks = get_all_checks()
    scheduler = Scheduler(checks=checks, timeout=max(cfg.web.timeout, cfg.k8s.timeout))
    enabled = set(cfg.web.enabled_checks) | set(cfg.k8s.enabled_checks)
    report = asyncio.run(scheduler.run(target=url, k8s_ctx=k8s_ctx, enabled_ids=enabled))
    _run(report, cfg, strict=strict)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
