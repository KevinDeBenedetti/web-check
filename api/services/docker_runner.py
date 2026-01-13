"""Docker container execution utilities."""

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


async def check_docker_container(container_name: str) -> bool:
    """
    Check if a Docker container is running.

    Args:
        container_name: Name of the container to check

    Returns:
        True if container is running, False otherwise
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        return stdout.decode().strip() == "true"
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
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
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

            return {
                "stdout": "",
                "stderr": "Command timed out",
                "exit_code": -1,
                "timeout": True,
            }

        return {
            "stdout": stdout.decode() if stdout else "",
            "stderr": stderr.decode() if stderr else "",
            "exit_code": process.returncode or 0,
            "timeout": False,
        }

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
        }


async def load_json_output(output_path: Path) -> dict[str, Any] | None:
    """
    Load JSON output from a scan result file.

    Args:
        output_path: Path to the JSON file

    Returns:
        Parsed JSON data or None if file doesn't exist or is invalid
    """
    try:
        if not output_path.exists():
            logger.warning("output_file_not_found", path=str(output_path))
            return None

        def _read_file() -> str:
            return output_path.read_text()

        content: str = await asyncio.to_thread(_read_file)
        data: dict[str, Any] = json.loads(content)
        return data

    except json.JSONDecodeError as e:
        logger.error("json_parse_error", path=str(output_path), error=str(e))
        return None
    except Exception as e:
        logger.error("file_read_error", path=str(output_path), error=str(e))
        return None


async def load_jsonl_output(output_path: Path) -> list[dict[str, Any]]:
    """
    Load JSONL output from a scan result file (one JSON object per line).

    Args:
        output_path: Path to the JSONL file

    Returns:
        List of parsed JSON objects
    """
    try:
        if not output_path.exists():
            logger.warning("output_file_not_found", path=str(output_path))
            return []

        def _read_file() -> str:
            return output_path.read_text()

        content: str = await asyncio.to_thread(_read_file)
        results: list[dict[str, Any]] = []

        for line in content.strip().split("\n"):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return results

    except Exception as e:
        logger.error("jsonl_read_error", path=str(output_path), error=str(e))
        return []
