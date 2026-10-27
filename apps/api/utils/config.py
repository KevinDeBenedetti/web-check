"""Configuration management for Web-Check."""

import json
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    # API Configuration
    debug: bool = False

    # Docker Configuration
    docker_network: str = "scanner-net"
    output_base_dir: Path = Path("outputs")

    # Database Configuration
    database_path: Path = Path("data/web-check.db")

    # Web UI: directory holding the built front-end (apps/web/dist by default)
    web_dist_dir: Path | None = None

    # Scan Defaults
    default_timeout: int = 300
    max_timeout: int = 3600

    # Logging
    log_level: str = "INFO"

    # SSRF / domain allowlist — comma-separated string.
    # Set ALLOWED_DOMAINS="example.com,yourdomain.com" in .env or environment.
    allowed_domains: str = "example.com"

    # Allow targets that are (or resolve to) private/loopback IPs or single-label
    # hostnames. Only enable this to scan lab environments on a trusted network.
    allow_private_targets: bool = False

    # API authentication — when set, every scan endpoint requires `X-API-Key`.
    api_key: SecretStr | None = None

    # CORS — comma-separated list of allowed origins (empty = CORS disabled).
    cors_origins: str = ""

    # OWASP ZAP daemon
    zap_host: str = "zap"
    zap_port: int = 8090
    zap_api_key: SecretStr | None = None

    def get_allowed_domains(self) -> list[str]:
        """Return allowed_domains as a parsed list (comma-separated or JSON array)."""
        v = self.allowed_domains.strip()
        if v.startswith("["):
            return json.loads(v)
        return [d.strip() for d in v.split(",") if d.strip()]

    def get_cors_origins(self) -> list[str]:
        """Return cors_origins as a parsed list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
