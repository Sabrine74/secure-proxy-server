"""OAuth2 / JWT authentication: validate a Bearer token and extract identity.

Given an 'Authorization: Bearer <jwt>' header value, verify the token's
signature, expiry, issuer and audience. On success, return the identity
(the standard 'sub' claim). On failure, return None plus a clear reason.
"""
from __future__ import annotations

import jwt

from .config_loader import OAuth2Config


class OAuth2Provider:
    def __init__(self, config: OAuth2Config):
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def authenticate(self, authorization_header: str | None) -> tuple[str | None, str]:
        """Validate a Bearer token. Returns (identity, reason)."""
        if not self.enabled:
            return None, "OAuth2 disabled"
        if not authorization_header:
            return None, "no Authorization header"
        if not authorization_header.lower().startswith("bearer "):
            return None, "not a Bearer token"

        token = authorization_header.split(None, 1)[1].strip()
        try:
            claims = jwt.decode(
                token,
                self.config.secret,
                algorithms=["HS256"],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            return None, "token expired"
        except jwt.InvalidTokenError as exc:
            return None, f"invalid token: {exc}"

        return str(claims["sub"]), "valid JWT"
