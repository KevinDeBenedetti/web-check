"""CLI configuration and settings."""

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class CLISettings(BaseSettings):
    """CLI application settings."""

    api_url: str = "http://localhost:8000"
    api_timeout: int = 600
    output_format: str = "table"  # table, json, yaml
    debug: bool = False
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="WEB_CHECK_CLI_",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def domains(self) -> list[str]:
        """Get allowed domains from ALLOWED_DOMAINS env var or .env file.

        This reads the shared ALLOWED_DOMAINS variable (no CLI prefix)
        used by both the API and CLI.
        """
        raw = os.getenv("ALLOWED_DOMAINS", "")
        if not raw:
            env_path = Path(".env")
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    stripped = line.strip()
                    if stripped.startswith("ALLOWED_DOMAINS="):
                        raw = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        if not raw:
            return []
        return [d.strip() for d in raw.split(",") if d.strip()]


def get_settings() -> CLISettings:
    """Get CLI settings instance."""
    return CLISettings()
