"""Security-focused scan endpoints."""

from datetime import timezone

from fastapi import APIRouter, HTTPException, Query

from api.models import CheckResult

router = APIRouter()


@router.get("/ffuf", response_model=CheckResult)
async def security_ffuf_scan(
    url: str = Query(..., description="Target URL to fuzz"),
    wordlist: str = Query("common.txt", description="Wordlist to use for fuzzing"),
    timeout: int = Query(600, ge=60, le=1800, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run FFUF directory/file fuzzing scan.

    Discovers hidden directories, files, and endpoints.
    Average duration: 5-15 minutes depending on wordlist size.
    """
    import time
    from datetime import datetime

    from api.services.docker_runner import docker_run

    start = time.time()

    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    try:
        result = await docker_run(
            image="secsi/ffuf:latest",
            command=[
                "ffuf",
                "-u",
                f"{url}/FUZZ",
                "-w",
                f"/wordlists/{wordlist}",
                "-o",
                "/output/ffuf.json",
                "-of",
                "json",
                "-mc",
                "200,204,301,302,307,401,403",
            ],
            volumes={
                "outputs/temp": "/output",
                "config/wordlists": "/wordlists:ro",
            },
            timeout=timeout,
            container_name="security-scanner-ffuf",
        )

        if result["timeout"]:
            return CheckResult(
                module="ffuf",
                category="security",
                target=url,
                timestamp=datetime.now(timezone.utc),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        return CheckResult(
            module="ffuf",
            category="security",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"wordlist": wordlist},
            findings=[],
            error=None,)

    except Exception as e:
        return CheckResult(
            module="ffuf",
            category="security",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )


@router.get("/sqlmap", response_model=CheckResult)
async def security_sqlmap_scan(
    url: str = Query(..., description="Target URL to test for SQL injection"),
    timeout: int = Query(900, ge=300, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run SQLMap SQL injection testing.

    Automatically detects and exploits SQL injection vulnerabilities.
    Average duration: 10-20 minutes.
    """
    import time
    from datetime import datetime

    from api.services.docker_runner import docker_run

    start = time.time()

    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    try:
        result = await docker_run(
            image="googlesky/sqlmap:latest",
            command=[
                "sqlmap",
                "-u",
                url,
                "--batch",
                "--random-agent",
                "--output-dir=/output",
            ],
            volumes={"outputs/temp": "/output"},
            timeout=timeout,
            container_name="security-scanner-sqlmap",
        )

        if result["timeout"]:
            return CheckResult(
                module="sqlmap",
                category="security",
                target=url,
                timestamp=datetime.now(timezone.utc),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        return CheckResult(
            module="sqlmap",
            category="security",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"scan_completed": True},
            findings=[],
            error=None,)

    except Exception as e:
        return CheckResult(
            module="sqlmap",
            category="security",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
