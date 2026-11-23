"""Security-focused scan endpoints."""

from api.models import CheckResult
from api.services.ffuf_scanner import run_ffuf_scan
from api.utils.security import target_url, validate_wordlist
from fastapi import APIRouter, Depends, Query

router = APIRouter()


@router.get("/ffuf", response_model=CheckResult)
async def security_ffuf_scan(
    url: str = Depends(target_url),
    wordlist: str = Query(
        "common.txt", description="Wordlist filename (from apps/config/wordlists/)"
    ),
    timeout: int = Query(600, ge=60, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run FFUF directory/file fuzzing scan.

    Discovers hidden directories, files, and endpoints, reported as informational
    findings. Needs the ffuf container (`docker compose --profile tools up -d`).
    Average duration: 5-15 minutes depending on wordlist size.
    """
    return await run_ffuf_scan(url, validate_wordlist(wordlist), timeout)


# SQL injection testing lives at /api/advanced/sqlmap (sqlmap runs inside the API
# container); the former /api/security/sqlmap called a container that never existed.
