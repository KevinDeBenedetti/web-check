"""Configuration schema and loader for my-check.

Priority (highest → lowest):
  1. CLI flags
  2. my-check.config.json file
  3. MY_CHECK_* environment variables
  4. Built-in defaults
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, Field, field_validator

# Load .env, walking up from cwd (override=False keeps existing shell env vars intact)
load_dotenv(find_dotenv(usecwd=True), override=False)

logger = logging.getLogger(__name__)

_DEFAULT_WEB_CHECKS = [
    "web-tls",
    "web-headers",
    "web-csp",
    "web-cors",
    "web-cookies",
    "web-dns",
    "web-ports",
    "web-redirects",
    "web-subdomain-takeover",
]

_DEFAULT_K8S_CHECKS = [
    "k8s-rbac",
    "k8s-workloads",
    "k8s-network-policies",
    "k8s-secrets",
    "k8s-images",
    "k8s-pss-compliance",
    "k8s-etcd-encryption",
    "k8s-kube-bench",
    "k8s-trivy",
    "k8s-polaris",
    "k8s-falco",
]


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_bool(key: str, default: bool = False) -> bool:
    return _env(key, "true" if default else "false").lower() in ("1", "true", "yes")


class WebConfig(BaseModel):
    """Configuration for web checks."""

    targets: list[str] = Field(default_factory=list)
    enabled_checks: list[str] = Field(default_factory=lambda: list(_DEFAULT_WEB_CHECKS))
    timeout: float = Field(30.0, ge=1.0)
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443, 3000, 3443, 9090])

    @field_validator("targets", mode="before")
    @classmethod
    def _coerce_targets(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v


class K8sConfig(BaseModel):
    """Configuration for Kubernetes checks."""

    context: str | None = Field(None)
    kubeconfig: str | None = Field(None)
    server: str | None = Field(None, description="Override API server URL (e.g. https://IP:6443)")
    namespace: str | None = Field(None)
    enabled_checks: list[str] = Field(default_factory=lambda: list(_DEFAULT_K8S_CHECKS))
    timeout: float = Field(60.0, ge=1.0)


class OutputConfig(BaseModel):
    """Configuration for output / reporters."""

    formats: list[str] = Field(default_factory=lambda: ["terminal"])
    output_dir: str = Field("outputs")
    sarif: bool = Field(False)
    webhook_url: str | None = Field(None)
    previous_report: str | None = Field(None)


class MyCheckConfig(BaseModel):
    """Root configuration for my-check."""

    web: WebConfig = Field(default_factory=WebConfig)
    k8s: K8sConfig = Field(default_factory=K8sConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


# ---------------------------------------------------------------------------
# Config file discovery & loading
# ---------------------------------------------------------------------------

_CONFIG_FILENAMES = ["my-check.config.json", ".my-check.json"]


def find_config_file(start: Path | None = None) -> Path | None:
    """Walk up from *start* (default cwd) looking for a config file."""
    directory = (start or Path.cwd()).resolve()
    for _ in range(20):
        for name in _CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        parent = directory.parent
        if parent == directory:
            break
        directory = parent
    return None


def _defaults_from_env() -> dict[str, Any]:
    """Build a partial config dict from MY_CHECK_* environment variables."""
    data: dict[str, Any] = {}

    # Web
    if web_target := _env("MY_CHECK_WEB_TARGET"):
        data.setdefault("web", {})["targets"] = [web_target]

    # K8s
    k8s: dict[str, Any] = {}
    if v := _env("MY_CHECK_K8S_CONTEXT"):
        k8s["context"] = v
    if v := _env("MY_CHECK_K8S_KUBECONFIG"):
        k8s["kubeconfig"] = v
    if v := _env("MY_CHECK_K8S_SERVER"):
        k8s["server"] = v
    if v := _env("MY_CHECK_K8S_NAMESPACE"):
        k8s["namespace"] = v
    if k8s:
        data["k8s"] = k8s

    # Output
    output: dict[str, Any] = {}
    if v := _env("MY_CHECK_OUTPUT"):
        output["formats"] = [f.strip() for f in v.split(",")]
    if v := _env("MY_CHECK_OUTPUT_DIR"):
        output["output_dir"] = v
    if "MY_CHECK_SARIF" in os.environ:
        output["sarif"] = _env_bool("MY_CHECK_SARIF")
    if v := _env("MY_CHECK_WEBHOOK_URL"):
        output["webhook_url"] = v
    if output:
        data["output"] = output

    return data


def load_config(path: Path | None = None) -> MyCheckConfig:
    """Load config, merging env vars → file → CLI flags (lowest → highest)."""
    # Start from env-var defaults
    data = _defaults_from_env()

    # Merge config file on top (file wins over env)
    config_path = path or find_config_file()
    if config_path:
        logger.info("Loading config from %s", config_path)
        file_data = json.loads(config_path.read_text(encoding="utf-8"))
        _deep_merge(data, file_data)
    else:
        logger.debug("No config file found — using env + defaults")

    return MyCheckConfig.model_validate(data)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Merge *override* into *base* in-place.

    - Nested dicts are merged recursively, not replaced.
    - ``None`` values in *override* are skipped so that env-var defaults survive
      a config file that has explicit ``null`` placeholders.
    """
    for key, value in override.items():
        if value is None:
            continue  # null in config file = "fall back to env / built-in default"
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
