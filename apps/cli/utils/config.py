"""CLI configuration and settings."""

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
    )


def get_settings() -> CLISettings:
    """Get CLI settings instance."""
    return CLISettings()
