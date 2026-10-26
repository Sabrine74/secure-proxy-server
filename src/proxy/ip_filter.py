"""IP filtering (CIDR) — the first stage of the security pipeline.

Runs before any parsing or authentication: a rejected address costs us
only one address comparison, not a full request cycle.
"""
from __future__ import annotations

import ipaddress
import logging

from .config_loader import IPFilterConfig


class IPFilter:
    def __init__(self, config: IPFilterConfig):
        self.config = config
        self.log = logging.getLogger("secure_proxy")
        self.whitelist = self._parse(config.whitelist)
        self.blacklist = self._parse(config.blacklist)

    @staticmethod
    def _parse(entries) -> list:
        networks = []
        for entry in entries or []:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logging.getLogger("secure_proxy").error(
                    "Invalid CIDR in ip_filter config: %r (ignored)", entry)
        return networks

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def is_allowed(self, client_ip: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        if not self.enabled:
            return True, "IP filter disabled"
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return False, f"unparsable client address {client_ip!r}"

        # Blacklist always wins
        for net in self.blacklist:
            if addr in net:
                return False, f"IP {client_ip} is blacklisted ({net})"

        # If a whitelist exists, the address must be in it
        if self.whitelist:
            for net in self.whitelist:
                if addr in net:
                    return True, f"IP {client_ip} whitelisted ({net})"
            return False, f"IP {client_ip} not in whitelist"

        return True, "IP allowed"
