"""LDAP authentication: bind with username/password, then map group -> role.

Given a username and password (typically from HTTP Basic auth), bind to the
directory as that user (proves the password is correct), then search the
groups the user belongs to and map the first matching group to a role.
"""
from __future__ import annotations
import base64

from ldap3 import Server, Connection, ALL, SUBTREE

from .config_loader import LDAPConfig


def parse_basic_auth(authorization_header: str | None) -> tuple[str, str] | None:
    """Decode 'Authorization: Basic <base64>' into (username, password)."""
    if not authorization_header or not authorization_header.lower().startswith("basic "):
        return None
    encoded = authorization_header.split(None, 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


class LDAPProvider:
    def __init__(self, config: LDAPConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def authenticate(self, authorization_header: str | None) -> tuple[str | None, str | None, str]:
        """Validate Basic credentials against LDAP. Returns (identity, role, reason)."""
        if not self.enabled:
            return None, None, "LDAP disabled"

        creds = parse_basic_auth(authorization_header)
        if creds is None:
            return None, None, "no Basic Authorization header"
        username, password = creds
        if not password:
            return None, None, "empty password rejected"

        user_dn = self.config.user_dn_template.format(username=username)

        try:
            server = Server(self.config.server, get_info=ALL)
            conn = Connection(server, user=user_dn, password=password)
            if not conn.bind():
                return None, None, "invalid credentials"
        except Exception as exc:
            return None, None, f"LDAP error: {exc}"

        role = self._resolve_role(conn, user_dn)
        conn.unbind()
        return username, role, f"LDAP OK, role={role}"

    def _resolve_role(self, conn: Connection, user_dn: str) -> str:
        """Search groups under group_base_dn that list this user as a member."""
        conn.search(
            search_base=self.config.group_base_dn,
            search_filter=f"(member={user_dn})",
            search_scope=SUBTREE,
            attributes=["cn"],
        )
        for entry in conn.entries:
            group_name = str(entry.cn)
            if group_name in self.config.group_role_map:
                return self.config.group_role_map[group_name]
        return "guest"
