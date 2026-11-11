"""Subprocess and Docker execution utilities.

Everything a scanner sends back — stdout, stderr, output files — is untrusted and
unbounded: it is read with a byte limit, decoded leniently and refused when
malformed, so a scanner can neither exhaust the API's memory nor make a scan look
successful with output the API could not interpret.
"""

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

import structlog
from api.utils.config import get_settings

logger = structlog.get_logger()

_CHUNK_SIZE = 64 * 1024


class ToolOutputError(RuntimeError):
    """A scanner produced output the API refuses to interpret (too large or malformed)."""

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"{tool}: {reason}")
        self.tool = tool
        self.reason = reason


def unique_output_name(prefix: str, extension: str) -> str:
    """Return a collision-free output filename (concurrent scans share ./outputs)."""
    return f"{prefix}_{uuid.uuid4().hex}.{extension}"


def write_private_file(path: Path, content: str) -> None:
    """Create ``path`` readable by the API user only; refuse to overwrite an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


async def read_bounded(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, int]:
    """Read a stream to EOF keeping at most ``limit`` bytes; return (kept, total bytes).

    The stream is always drained, so the child process never blocks on a full pipe.
    """
    kept = bytearray()
    total = 0
    while chunk := await stream.read(_CHUNK_SIZE):
        total += len(chunk)
        if len(kept) < limit:
            kept += chunk[: limit - len(kept)]
    return bytes(kept), total


def _decode(data: bytes, total: int, limit: int) -> str:
    text = data.decode("utf-8", errors="replace")
    if total > limit:
        text += f"\n[output truncated: {total} bytes produced, {limit} kept]"
    return text


async def run_process(
    cmd: list[str], *, timeout: float, output_limit: int | None = None
) -> dict[str, Any]:
    """Run ``cmd`` (argv, never a shell) with a deadline and bounded output capture.

    Returns stdout/stderr as text (invalid UTF-8 replaced), the exit code, whether
    the deadline killed the process and whether any output was truncated.
    """
    limit = output_limit or get_settings().tool_output_max_bytes
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    assert process.stdout is not None and process.stderr is not None
    try:
        async with asyncio.timeout(timeout):
            (out, out_total), (err, err_total) = await asyncio.gather(
                read_bounded(process.stdout, limit), read_bounded(process.stderr, limit)
            )
            await process.wait()
    except TimeoutError:
        process.kill()
        await process.wait()
        return {
            "stdout": "",
            "stderr": "Command timed out",
            "exit_code": -1,
            "timeout": True,
            "truncated": False,
        }
    return {
        "stdout": _decode(out, out_total, limit),
        "stderr": _decode(err, err_total, limit),
        "exit_code": process.returncode or 0,
        "timeout": False,
        "truncated": out_total > limit or err_total > limit,
    }


async def check_docker_container(container_name: str) -> bool:
    """
    Check if a Docker container is running.

    Args:
        container_name: Name of the container to check

    Returns:
        True if container is running, False otherwise
    """
    try:
        result = await run_process(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            timeout=10,
            output_limit=4096,
        )
        return result["stdout"].strip() == "true"
    except Exception as e:
        logger.error("container_check_failed", container=container_name, error=str(e))
        return False


async def docker_run(
    image: str,
    command: list[str],
    volumes: dict[str, str] | None = None,
    timeout: int = 300,
    container_name: str | None = None,
    network: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """
    Run a Docker container and return the results.

    Args:
        image: Docker image to use
        command: Command to run in the container
        volumes: Dictionary mapping host paths to container paths
        timeout: Maximum execution time in seconds
        container_name: Name for the container (for docker exec)
        network: Docker network to use
        scan_id: Scan ID for streaming logs (optional)

    Returns:
        Dictionary with stdout, stderr, and exit code
    """
    if container_name:
        # Use existing container with docker exec
        cmd = ["docker", "exec", container_name] + command
    else:
        # Run new container
        cmd = ["docker", "run", "--rm"]

        if volumes:
            for host_path, container_path in volumes.items():
                cmd.extend(["-v", f"{host_path}:{container_path}"])

        if network:
            cmd.extend(["--network", network])

        cmd.append(image)
        cmd.extend(command)

    logger.info("running_docker_command", command=" ".join(cmd))

    # Stream logs if scan_id provided
    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id,
            {
                "type": "docker",
                "message": f"Executing: {image}",
                "command": " ".join(command),
            },
        )

    try:
        result = await run_process(cmd, timeout=timeout)
    except Exception as e:
        logger.error("docker_command_failed", command=" ".join(cmd), error=str(e))

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "error",
                    "message": f"Docker command failed: {str(e)}",
                },
            )

        return {
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "timeout": False,
            "truncated": False,
        }

    if result["timeout"]:
        logger.warning("docker_command_timeout", command=" ".join(cmd))

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "warning",
                    "message": f"Command timed out after {timeout}s",
                },
            )
    elif result["truncated"]:
        logger.warning("docker_command_output_truncated", command=" ".join(cmd))

    return result


def _read_output_file(output_path: Path, tool: str) -> str:
    limit = get_settings().tool_file_max_bytes
    size = output_path.stat().st_size
    if size > limit:
        raise ToolOutputError(tool, f"output file is {size} bytes, the limit is {limit}")
    return output_path.read_bytes().decode("utf-8", errors="replace")


async def load_json_output(output_path: Path, tool: str = "scanner") -> dict[str, Any] | None:
    """
    Load the JSON object a scanner wrote to ``output_path``.

    Returns None when the file does not exist. Raises ToolOutputError when the file
    is larger than TOOL_FILE_MAX_BYTES or is not a JSON object.
    """
    if not output_path.exists():
        logger.warning("output_file_not_found", path=str(output_path))
        return None

    content = await asyncio.to_thread(_read_output_file, output_path, tool)
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ToolOutputError(tool, f"invalid JSON output: {e.msg}") from e
    if not isinstance(data, dict):
        raise ToolOutputError(tool, "JSON output is not an object")
    return data


async def load_jsonl_output(output_path: Path, tool: str = "scanner") -> list[dict[str, Any]]:
    """
    Load the JSON Lines a scanner wrote to ``output_path`` (one object per line).

    Returns [] when the file does not exist. Raises ToolOutputError when the file is
    larger than TOOL_FILE_MAX_BYTES or a non-empty line is not a JSON object.
    """
    if not output_path.exists():
        logger.warning("output_file_not_found", path=str(output_path))
        return []

    content = await asyncio.to_thread(_read_output_file, output_path, tool)
    results: list[dict[str, Any]] = []
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as e:
            raise ToolOutputError(tool, f"invalid JSON on line {number}: {e.msg}") from e
        if not isinstance(item, dict):
            raise ToolOutputError(tool, f"line {number} is not a JSON object")
        results.append(item)
    return results
