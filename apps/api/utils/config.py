"""Configuration management for Web-Check."""

import json
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    # API Configuration
    api_title: str = "Web-Check Security Scanner"
    api_version: str = "0.1.0"
    debug: bool = False

    # Docker Configuration
    docker_network: str = "scanner-net"
    output_base_dir: Path = Path("outputs")

    # Database Configuration
    database_path: Path = Path("data/web-check.db")

    # Scan Defaults
    default_timeout: int = 300
    max_timeout: int = 3600

    # Logging
    log_level: str = "INFO"

    # SSRF / domain allowlist — comma-separated string.
    # Set ALLOWED_DOMAINS="example.com,yourdomain.com" in .env or environment.
    allowed_domains: str = "example.com"

    def get_allowed_domains(self) -> list[str]:
        """Return allowed_domains as a parsed list (comma-separated or JSON array)."""
        v = self.allowed_domains.strip()
        if v.startswith("["):
            return json.loads(v)
        return [d.strip() for d in v.split(",") if d.strip()]

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
