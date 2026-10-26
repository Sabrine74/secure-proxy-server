"""Structured JSON access logging — one line per request, machine-readable.

This is separate from logger_setup.py (the human-readable console/file
log). This module writes to logs/access.jsonl, one JSON object per line
(the ".jsonl" convention: JSON Lines, easy to read one record at a time
without loading the whole file).
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

_ACCESS_LOGGER_NAME = "secure_proxy.access"


def setup_access_log(path: str = "logs/access.jsonl") -> logging.Logger:
    """Create a dedicated logger that writes raw JSON lines to a file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    # Name the logger after its target file so distinct calls to this
    # function (e.g. one per test, or a future second instance) each get
    # their own independent logger instead of silently sharing state.
    logger = logging.getLogger(f"{_ACCESS_LOGGER_NAME}.{path}")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't also send these to the console logger

    if not logger.handlers:
        handler = logging.FileHandler(path, encoding="utf-8")
        # no formatting — we hand it a fully-formed JSON string
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    return logger


def log_access(logger: logging.Logger, *, client_ip: str, method: str,
                path: str, identity: str | None, role: str | None,
                decision: str, reason: str, duration_ms: float) -> None:
    """Write one structured record for a completed request."""
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "identity": identity,
        "role": role,
        "decision": decision,       # "allow" or the HTTP status that blocked it
        "reason": reason,
        "duration_ms": round(duration_ms, 2),
    }
    logger.info(json.dumps(record, ensure_ascii=False))
