"""Plain HTTP listener on :8080 — health check only, never forwards traffic.
Exists to demonstrate the contrast: no TLS, no auth, minimal response only."""
from __future__ import annotations
import asyncio
import logging


async def _handle(reader, writer):
    log = logging.getLogger("secure_proxy")
    try:
        await asyncio.wait_for(reader.read(1024), timeout=2)
    except Exception:
        pass
    body = b'{"service": "secure-proxy", "note": "plain HTTP - health check only, no forwarding"}'
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    writer.write(resp)
    await writer.drain()
    writer.close()
    log.info("HTTP health check served (plain, :8080)")


async def start_health_listener(host: str, port: int):
    log = logging.getLogger("secure_proxy")
    server = await asyncio.start_server(_handle, host=host, port=port)
    log.info("Health listener (plain HTTP, no forwarding) on %s:%d", host, port)
    return server
