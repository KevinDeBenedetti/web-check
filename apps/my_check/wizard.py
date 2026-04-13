"""Interactive step-by-step wizard for my-check."""

from __future__ import annotations

import asyncio
from typing import Any

import questionary
import typer
from my_check.config import MyCheckConfig, load_config
from my_check.registry import get_all_checks, get_k8s_checks, get_web_checks
from my_check.scheduler import Scheduler
from my_check.types import CheckCategory, K8sContext, Report
from questionary import Style
from rich.console import Console
from rich.rule import Rule
from rich.text import Text

console = Console()

# ── Questionary style (matches Rich cyan/yellow palette) ─────────────────────
_STYLE = Style(
    [
        ("qmark", "fg:#00d7ff bold"),
        ("question", "bold"),
        ("answer", "fg:#00d7ff bold"),
        ("pointer", "fg:#00d7ff bold"),
        ("highlighted", "fg:#00d7ff bold"),
        ("selected", "fg:#00ff87"),
        ("separator", "fg:#555555"),
        ("instruction", "fg:#888888 italic"),
        ("text", ""),
        ("disabled", "fg:#555555 italic"),
    ]
)

_WEB_CHECK_CHOICES = [
    ("web-tls         — TLS certificate expiry & chain", "web-tls"),
    ("web-headers     — Security headers (CSP, HSTS, …)", "web-headers"),
    ("web-dns         — DNS security (DNSSEC, CAA, SPF, DMARC)", "web-dns"),
    ("web-ports       — Exposed ports (TCP scan)", "web-ports"),
    ("web-redirects   — Redirect chain & HTTP→HTTPS", "web-redirects"),
    ("web-subdomain-takeover — Subdomain takeover via CNAME", "web-subdomain-takeover"),
]

_K8S_CHECK_CHOICES = [
    ("k8s-rbac              — RBAC wildcard verbs & anonymous bindings", "k8s-rbac"),
    ("k8s-workloads         — Privileged / root containers", "k8s-workloads"),
    ("k8s-network-policies  — NetworkPolicy coverage", "k8s-network-policies"),
    ("k8s-secrets           — Plain env secrets / missing sealed secrets", "k8s-secrets"),
    ("k8s-images            — :latest tags without SHA digest", "k8s-images"),
    ("k8s-kube-bench        — CIS benchmarks (kube-bench wrapper)", "k8s-kube-bench"),
    ("k8s-trivy             — Vulnerability scan (trivy wrapper)", "k8s-trivy"),
    ("k8s-polaris           — Best practices (polaris wrapper)", "k8s-polaris"),
    ("k8s-falco             — Falco DaemonSet runtime health", "k8s-falco"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _header(title: str) -> None:
    console.print()
    console.print(Rule(Text(title, style="bold cyan")))
    console.print()


def _step(n: int, label: str) -> None:
    console.print(f"[bold yellow]Step {n}[/bold yellow] — [bold]{label}[/bold]")
    console.print()


def _q(prompt: Any) -> Any:
    """Ask a questionary prompt; raise typer.Exit on Ctrl-C / empty answer."""
    result = prompt.ask()
    if result is None:
        console.print("\n[dim]Cancelled.[/dim]")
        raise typer.Exit()
    return result


def _load_kube_contexts() -> list[str]:
    """Return available kubeconfig context names, or [] on failure."""
    try:
        from kubernetes import config as kconf

        contexts, _ = kconf.list_kube_config_contexts()
        return [c["name"] for c in contexts] if contexts else []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main wizard
# ---------------------------------------------------------------------------


def run_wizard() -> None:
    """Launch the interactive step-by-step security scan wizard."""
    _header("🔒  my-check — Security Scanner")
    console.print(
        "  [dim]Use arrow keys ↑↓ to navigate, Space to select, Enter to confirm.[/dim]"
    )

    cfg = load_config()

    # ── Step 1: mode ──────────────────────────────────────────────────────
    _step(1, "What do you want to scan?")
    mode: str = _q(
        questionary.select(
            "Scan target",
            choices=[
                questionary.Choice("🌐  Web — website / API endpoint", value="web"),
                questionary.Choice("☸️   Kubernetes / k3s cluster", value="k8s"),
                questionary.Choice("🔍  All — web + Kubernetes", value="all"),
            ],
            default="web",
            style=_STYLE,
        )
    )
    do_web = mode in ("web", "all")
    do_k8s = mode in ("k8s", "all")

    # ── Step 2a: web target ───────────────────────────────────────────────
    url: str | None = None
    if do_web:
        _step(2, "Web target URL")
        default_url = cfg.web.targets[0] if cfg.web.targets else "https://example.com"
        url = _q(
            questionary.text(
                "Target URL",
                default=default_url,
                style=_STYLE,
            )
        ).strip()

    # ── Step 2b / 3: K8s cluster ──────────────────────────────────────────
    k8s_ctx: K8sContext | None = None
    if do_k8s:
        step_n = 3 if do_web else 2
        _step(step_n, "Kubernetes cluster")

        # Context — pull available ones from kubeconfig
        kube_contexts = _load_kube_contexts()
        default_ctx = cfg.k8s.context

        if kube_contexts:
            ctx_choices = [questionary.Choice(c, value=c) for c in kube_contexts]
            ctx_choices.append(questionary.Choice("✏️   Enter manually…", value="__manual__"))
            selected_ctx: str = _q(
                questionary.select(
                    "Kubeconfig context",
                    choices=ctx_choices,
                    default=default_ctx if default_ctx in kube_contexts else kube_contexts[0],
                    style=_STYLE,
                )
            )
            if selected_ctx == "__manual__":
                selected_ctx = _q(
                    questionary.text("Enter context name", default=default_ctx or "", style=_STYLE)
                ).strip()
        else:
            selected_ctx = _q(
                questionary.text(
                    "Kubeconfig context (kubectl config get-contexts)",
                    default=default_ctx or "",
                    style=_STYLE,
                )
            ).strip()

        # Kubeconfig path
        default_kb = cfg.k8s.kubeconfig or ""
        kubeconfig: str = _q(
            questionary.text(
                "Kubeconfig path (blank = ~/.kube/config)",
                default=default_kb,
                style=_STYLE,
            )
        ).strip()

        # Namespace — offer common ones + manual
        ns_choices = [
            questionary.Choice("(all namespaces)", value=""),
            questionary.Choice("✏️   Enter manually…", value="__manual__"),
        ]
        selected_ns: str = _q(
            questionary.select(
                "Namespace",
                choices=ns_choices,
                style=_STYLE,
            )
        )
        if selected_ns == "__manual__":
            selected_ns = _q(
                questionary.text(
                    "Namespace", default=cfg.k8s.namespace or "", style=_STYLE
                )
            ).strip()

        k8s_ctx = K8sContext(
            context_name=selected_ctx or None,
            kubeconfig_path=kubeconfig or None,
            namespace=selected_ns or None,
        )

    # ── Step 3/4: check selection ─────────────────────────────────────────
    step_n = (3 if do_web else 2) + (1 if do_k8s else 0)
    _step(step_n, "Select checks")
    step_n += 1

    enabled_web = list(cfg.web.enabled_checks)
    enabled_k8s = list(cfg.k8s.enabled_checks)

    customize: bool = _q(
        questionary.confirm("Customize which checks to run?", default=False, style=_STYLE)
    )

    if customize:
        if do_web:
            console.print("[bold]Web checks:[/bold]")
            chosen = _q(
                questionary.checkbox(
                    "Select web checks (Space to toggle)",
                    choices=[
                        questionary.Choice(label, value=val, checked=(val in enabled_web))
                        for label, val in _WEB_CHECK_CHOICES
                    ],
                    style=_STYLE,
                )
            )
            enabled_web = chosen or enabled_web

        if do_k8s:
            console.print("[bold]Kubernetes checks:[/bold]")
            chosen = _q(
                questionary.checkbox(
                    "Select k8s checks (Space to toggle)",
                    choices=[
                        questionary.Choice(label, value=val, checked=(val in enabled_k8s))
                        for label, val in _K8S_CHECK_CHOICES
                    ],
                    style=_STYLE,
                )
            )
            enabled_k8s = chosen or enabled_k8s

    # ── Step 4/5: output format ───────────────────────────────────────────
    _step(step_n, "Output format")
    step_n += 1

    current_formats = cfg.output.formats
    format_choices = [
        questionary.Choice("terminal  — colored table (default)", value="terminal",
                           checked=("terminal" in current_formats)),
        questionary.Choice("markdown  — Markdown report file (.md)", value="markdown",
                           checked=("markdown" in current_formats)),
        questionary.Choice("json      — structured JSON + SARIF file", value="json",
                           checked=("json" in current_formats)),
        questionary.Choice("html      — self-contained HTML report", value="html",
                           checked=("html" in current_formats)),
        questionary.Choice("webhook   — POST to Slack / custom endpoint", value="webhook",
                           checked=("webhook" in current_formats)),
    ]
    chosen_formats: list[str] = _q(
        questionary.checkbox(
            "Output reporters (Space to toggle, at least one required)",
            choices=format_choices,
            style=_STYLE,
        )
    )
    formats = chosen_formats or ["terminal"]

    # ── Step 5/6: confirm ─────────────────────────────────────────────────
    _step(step_n, "Confirm & run")

    lines: list[str] = []
    if url:
        lines.append(f"  [dim]Web target :[/dim]  [cyan]{url}[/cyan]")
    if k8s_ctx:
        ctx_label = k8s_ctx.context_name or "current context"
        lines.append(f"  [dim]K8s context:[/dim]  [cyan]{ctx_label}[/cyan]")
        if k8s_ctx.namespace:
            lines.append(f"  [dim]Namespace   :[/dim]  [cyan]{k8s_ctx.namespace}[/cyan]")
    total = len(enabled_web) + len(enabled_k8s)
    lines.append(f"  [dim]Checks     :[/dim]  [cyan]{total} selected[/cyan]")
    lines.append(f"  [dim]Output     :[/dim]  [cyan]{', '.join(formats)}[/cyan]")
    for line in lines:
        console.print(line)
    console.print()

    if not _q(questionary.confirm("Run scan?", default=True, style=_STYLE)):
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit()

    # ── Run ───────────────────────────────────────────────────────────────
    console.print()
    _execute(
        cfg=cfg,
        url=url,
        k8s_ctx=k8s_ctx,
        enabled_web=enabled_web,
        enabled_k8s=enabled_k8s,
        formats=formats,
    )


def _execute(
    cfg: MyCheckConfig,
    url: str | None,
    k8s_ctx: K8sContext | None,
    enabled_web: list[str],
    enabled_k8s: list[str],
    formats: list[str],
) -> None:
    cfg.output.formats = formats

    if url and k8s_ctx:
        checks = get_all_checks()
        scheduler = Scheduler(checks=checks, timeout=max(cfg.web.timeout, cfg.k8s.timeout))
        enabled = set(enabled_web) | set(enabled_k8s)
        report = asyncio.run(scheduler.run(target=url, k8s_ctx=k8s_ctx, enabled_ids=enabled))
    elif url:
        checks = get_web_checks()
        scheduler = Scheduler(checks=checks, timeout=cfg.web.timeout)
        report = asyncio.run(
            scheduler.run(target=url, enabled_ids=set(enabled_web), category=CheckCategory.WEB)
        )
    else:
        checks = get_k8s_checks()
        scheduler = Scheduler(checks=checks, timeout=cfg.k8s.timeout)
        report = asyncio.run(
            scheduler.run(k8s_ctx=k8s_ctx, enabled_ids=set(enabled_k8s), category=CheckCategory.K8S)
        )

    _emit(report, cfg)


def _emit(report: Report, cfg: MyCheckConfig) -> None:
    from pathlib import Path

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
                    output_dir=output_dir, previous_report=cfg.output.previous_report
                ).emit(report)
            case "webhook":
                from my_check.reporters.webhook import WebhookReporter

                asyncio.run(WebhookReporter(url=cfg.output.webhook_url).emit(report))
            case _:
                console.print(f"[yellow]Unknown reporter: {fmt}[/yellow]")

    fail_count = report.summary.get("fail", 0)  # type: ignore[arg-type]
    raise typer.Exit(code=1 if fail_count > 0 else 0)
