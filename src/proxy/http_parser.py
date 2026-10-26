"""Minimal HTTP/1.1 request parser: turn raw bytes into a structured request."""
from __future__ import annotations
import asyncio

MAX_HEADER_BYTES = 65536


class HttpRequest:
    __slots__ = ("method", "path", "version", "headers", "raw_head")

    def __init__(self, method, path, version, headers, raw_head):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers          # dict, lowercased keys
        self.raw_head = raw_head        # original header bytes, to forward as-is

    def header(self, name):
        return self.headers.get(name.lower())


async def read_request(reader: asyncio.StreamReader) -> HttpRequest | None:
    """Read until the blank line that ends the headers, then parse."""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return None
    if len(head) > MAX_HEADER_BYTES:
        return None

    lines = head.decode("latin-1").split("\r\n")
    request_line = lines[0].split(" ")
    if len(request_line) != 3:
        return None
    method, path, version = request_line

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            return None
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return HttpRequest(method, path, version, headers, head)
