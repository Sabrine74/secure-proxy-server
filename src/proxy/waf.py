"""Web Application Firewall — scans request content for known attack
patterns and blocks matches. Runs last, right before forwarding: no
point scanning a request already rejected by an earlier layer.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import unquote

from .config_loader import WAFConfig

_PATTERNS = [
    ("sql_injection", re.compile(
        r"(\bunion\b.{0,20}\bselect\b|\bor\b\s+1\s*=\s*1|--\s|;\s*drop\b|'\s*or\s*')",
        re.IGNORECASE)),
    ("xss", re.compile(
        r"(<script\b|javascript:|onerror\s*=|onload\s*=)",
        re.IGNORECASE)),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)),
]


class WAF:
    def __init__(self, config: WAFConfig):
        self.config = config
        self.log = logging.getLogger("secure_proxy")

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def inspect(self, request) -> tuple[bool, str]:
        if not self.enabled:
            return True, "WAF disabled"

        # Decode URL-encoding first — otherwise an attacker can bypass
        # every pattern simply by percent-encoding the attack (' -> %27).
        haystack = unquote(request.path)
        for name, header_value in request.headers.items():
            haystack += " " + unquote(str(header_value))

        for pattern_name, regex in _PATTERNS:
            if regex.search(haystack):
                return False, f"blocked by WAF ({pattern_name})"

        return True, "clean"

    def sanitize_headers(self, headers: dict) -> dict:
        strip = {h.lower() for h in self.config.strip_headers}
        return {k: v for k, v in headers.items() if k.lower() not in strip}
