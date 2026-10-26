"""Scope models: the allowlist of targets this instance may scan."""

from pydantic import BaseModel, Field


class ScopeRules(BaseModel):
    """Configured scope rules."""

    rules: list[str] = Field(..., description="Allowed domains; '*.' prefix means subdomains only")
    source: str = Field("ALLOWED_DOMAINS", description="Where the rules are configured")


class ScopeCheckRequest(BaseModel):
    """Target to check against the scope rules."""

    target: str = Field(..., min_length=1, max_length=2048, description="URL or hostname")


class ScopeCheckResult(BaseModel):
    """Outcome of a scope check."""

    target: str
    hostname: str | None = Field(None, description="Hostname extracted from the target")
    allowed: bool
    matched_rule: str | None = Field(None, description="Rule that allowed the target")
