"""Rate limiting — sliding window, per client IP, quota by role.

Runs after RBAC: no point counting requests from someone we'd refuse anyway.
Keeps, for each IP, the timestamps of recent requests; drops those older than
the window; if what remains reaches the role's quota, the request is refused
with 429 and a Retry-After telling the client when to try again.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from .config_loader import RateLimitConfig


class RateLimiter:
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.log = logging.getLogger("secure_proxy")
        # one queue of timestamps per client IP
        self._hits: dict[str, deque] = defaultdict(deque)

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def quota_for(self, role: str) -> int:
        return self.config.quotas.get(role, self.config.default_quota)

    def check(self, client_ip: str, role: str) -> tuple[bool, str, int]:
        """Returns (allowed, reason, retry_after_seconds)."""
        if not self.enabled:
            return True, "rate limiting disabled", 0

        now = time.monotonic()
        window = self.config.window_seconds
        quota = self.quota_for(role)

        hits = self._hits[client_ip]
        # drop timestamps outside the sliding window
        while hits and hits[0] <= now - window:
            hits.popleft()

        if len(hits) >= quota:
            # how long until the oldest hit leaves the window
            retry_after = int(window - (now - hits[0])) + 1
            return False, f"rate limit exceeded ({quota}/{window}s for role '{role}')", retry_after

        hits.append(now)
        return True, f"{len(hits)}/{quota} in window", 0
