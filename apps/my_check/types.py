"""Shared types for the my-check security scanner."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class CheckCategory(StrEnum):
    """Category a check belongs to."""

    WEB = "web"
    K8S = "k8s"


class CheckStatus(StrEnum):
    """Outcome status for a single check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result produced by a single check execution."""

    status: CheckStatus
    score: int  # 0–100
    message: str
    details: Any = None
    remediation: str | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError(f"score must be 0–100, got {self.score}")


@dataclass(frozen=True, slots=True)
class K8sContext:
    """Kubernetes connection context."""

    context_name: str | None = None
    kubeconfig_path: str | None = None
    namespace: str | None = None
    # Run kube-bench as a privileged Job in the cluster instead of on this machine.
    kube_bench_job: bool = False

    def kubeconfig_env(self) -> dict[str, str] | None:
        """KUBECONFIG for tools that take no --kubeconfig flag (polaris, kube-bench)."""
        return {"KUBECONFIG": self.kubeconfig_path} if self.kubeconfig_path else None


@runtime_checkable
class Check(Protocol):
    """Protocol every check module must satisfy."""

    id: str
    name: str
    category: CheckCategory

    async def run(self, target: str | K8sContext) -> CheckResult: ...


@dataclass(slots=True)
class CheckEntry:
    """Registered check with its metadata."""

    check: Check
    enabled: bool = True


@dataclass(slots=True)
class Report:
    """Aggregated results from a full scan run."""

    target: str
    results: dict[str, CheckResult] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def global_score(self) -> float:
        # Exclude INFO-only results (e.g. tool-not-installed) from the average
        # so optional checks don't drag down the score.
        scores = [r.score for r in self.results.values() if r.status != CheckStatus.INFO]
        return sum(scores) / len(scores) if scores else 0.0

    @property
    def by_category(self) -> dict[CheckCategory, list[tuple[str, CheckResult]]]:
        grouped: dict[CheckCategory, list[tuple[str, CheckResult]]] = {}
        for check_id, result in self.results.items():
            # Infer category from check_id prefix
            cat = CheckCategory.K8S if check_id.startswith("k8s-") else CheckCategory.WEB
            grouped.setdefault(cat, []).append((check_id, result))
        return grouped

    @property
    def summary(self) -> dict[CheckStatus, int]:
        counts: dict[CheckStatus, int] = dict.fromkeys(CheckStatus, 0)
        for r in self.results.values():
            counts[r.status] += 1
        return counts


# ---------------------------------------------------------------------------
# Utility: run a subprocess with timeout and return stdout/stderr
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubprocessResult:
    """Result from running an external command."""

    returncode: int
    stdout: str
    stderr: str


async def run_subprocess(
    cmd: list[str],
    *,
    timeout: float = 120.0,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> SubprocessResult:
    """Run *cmd* asynchronously with a timeout. Returns SubprocessResult.

    *env* adds variables to the inherited environment (it does not replace it).
    *stdin* is written to the command's standard input.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **env} if env else None,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None),
            timeout=timeout,
        )
    except asyncio.CancelledError:
        # The check was cancelled (its own timeout): do not leave the command running.
        if proc.returncode is None:
            proc.kill()
            await proc.wait()  # reap it before the check's event loop closes
        raise
    except TimeoutError:
        proc.kill()
        await proc.communicate()
        return SubprocessResult(
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
        )
    return SubprocessResult(
        returncode=proc.returncode or 0,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
    )
