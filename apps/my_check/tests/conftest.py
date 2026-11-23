"""Shared fixtures: a minimal HTTP server on 127.0.0.1 for the web checks."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

# handler(path, request headers) -> (status line, response headers, body)
Handler = Callable[[str, dict[str, str]], tuple[str, list[tuple[str, str]], bytes]]


@pytest.fixture
async def http_server() -> AsyncIterator[Callable[[Handler], Awaitable[str]]]:
    servers: list[asyncio.AbstractServer] = []

    async def start(handler: Handler) -> str:
        async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request_line = await reader.readline()
            if not request_line.split():
                writer.close()
                return
            headers: dict[str, str] = {}
            while (line := await reader.readline()) not in (b"\r\n", b"\n", b""):
                name, _, value = line.decode().partition(":")
                headers[name.strip().lower()] = value.strip()
            status, response_headers, body = handler(request_line.split()[1].decode(), headers)
            head = f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n"
            head += "".join(f"{name}: {value}\r\n" for name, value in response_headers) + "\r\n"
            writer.write(head.encode() + body)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(on_connection, "127.0.0.1", 0)
        servers.append(server)
        return f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"

    yield start
    for server in servers:
        server.close()
        await server.wait_closed()
