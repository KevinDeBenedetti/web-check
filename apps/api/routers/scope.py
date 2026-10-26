"""Scope endpoints: which targets this instance is allowed to scan."""

from api.models.scope import ScopeCheckRequest, ScopeCheckResult, ScopeRules
from api.services.scope import check_scope
from api.utils.config import get_settings
from fastapi import APIRouter

router = APIRouter()


@router.get("", response_model=ScopeRules)
async def read_scope() -> ScopeRules:
    """Return the scope rules configured with ALLOWED_DOMAINS."""
    return ScopeRules(rules=get_settings().get_allowed_domains())


@router.post("/check", response_model=ScopeCheckResult)
async def check_target_scope(request: ScopeCheckRequest) -> ScopeCheckResult:
    """Check whether a target may be scanned, without contacting it."""
    decision = check_scope(request.target, get_settings().get_allowed_domains())
    return ScopeCheckResult(
        target=request.target,
        hostname=decision.hostname,
        allowed=decision.allowed,
        matched_rule=decision.matched_rule,
    )
