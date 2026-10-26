"""Role-Based Access Control — decides what an authenticated identity may do.

Authentication answers "who are you?"; this answers "are you allowed?".
Runs after authentication, since a role can only be checked once known.
"""
from __future__ import annotations

import logging

from .config_loader import RBACConfig


class RBAC:
    def __init__(self, config: RBACConfig):
        self.config = config
        self.log = logging.getLogger("secure_proxy")

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def role_for(self, source: str, ldap_role: str | None = None) -> str:
        """Determine the role from the identity source.

        LDAP supplies a real role from group membership; certificate and JWT
        identities fall back to the configured defaults.
        """
        if ldap_role:
            return ldap_role
        return self.config.default_roles.get(source, "guest")

    def is_allowed(self, role: str, method: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        if not self.enabled:
            return True, "RBAC disabled"

        allowed_methods = self.config.roles.get(role)
        if allowed_methods is None:
            return False, f"unknown role '{role}'"
        if method.upper() in [m.upper() for m in allowed_methods]:
            return True, f"role '{role}' may {method.upper()}"
        return False, f"role '{role}' may not {method.upper()}"
