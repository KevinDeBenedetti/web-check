"""Configuration management for Web-Check."""

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

    # Scan Defaults
    default_timeout: int = 300
    max_timeout: int = 3600

    # Logging
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
