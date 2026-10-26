"""BL3-05 — Unit tests: parser and authentication logic, no services required."""
import asyncio
import base64
import sys
import time

import jwt
import pytest

sys.path.insert(0, "src")

from proxy.config_loader import load_config
from proxy.http_parser import read_request
from proxy.oauth2_provider import OAuth2Provider
from proxy.ldap_provider import parse_basic_auth

CONFIG = load_config("config/policies.yaml")


def _parse(raw: bytes):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()
        return await read_request(reader)
    return asyncio.run(run())


def test_parser_extracts_request_line():
    req = _parse(b"GET /api/data HTTP/1.1\r\nHost: x\r\n\r\n")
    assert req.method == "GET"
    assert req.path == "/api/data"
    assert req.version == "HTTP/1.1"


def test_parser_extracts_headers_case_insensitively():
    req = _parse(b"GET / HTTP/1.1\r\nAuthorization: Bearer abc\r\nHost: x\r\n\r\n")
    assert req.header("authorization") == "Bearer abc"
    assert req.header("AUTHORIZATION") == "Bearer abc"


def test_parser_rejects_malformed_request_line():
    assert _parse(b"NONSENSE\r\nHost: x\r\n\r\n") is None


def test_parser_rejects_malformed_header():
    assert _parse(b"GET / HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n") is None


provider = OAuth2Provider(CONFIG.oauth2)
C = CONFIG.oauth2


def make_token(sub="alice", expired=False, secret=None, aud=None, iss=None):
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "iss": iss or C.issuer, "aud": aud or C.audience,
         "iat": now, "exp": now + (-3600 if expired else 3600)},
        secret or C.secret, algorithm="HS256")


def test_jwt_valid_token_returns_identity():
    identity, reason = provider.authenticate(f"Bearer {make_token('alice')}")
    assert identity == "alice"


def test_jwt_expired_token_rejected():
    identity, reason = provider.authenticate(f"Bearer {make_token(expired=True)}")
    assert identity is None
    assert "expired" in reason.lower()


def test_jwt_forged_signature_rejected():
    identity, _ = provider.authenticate(f"Bearer {make_token(secret='wrong-secret-value-1234567890')}")
    assert identity is None


def test_jwt_wrong_audience_rejected():
    identity, _ = provider.authenticate(f"Bearer {make_token(aud='other-service')}")
    assert identity is None


def test_jwt_wrong_issuer_rejected():
    identity, _ = provider.authenticate(f"Bearer {make_token(iss='https://evil.example.com')}")
    assert identity is None


def test_jwt_missing_header_rejected():
    identity, _ = provider.authenticate(None)
    assert identity is None


def test_jwt_non_bearer_scheme_rejected():
    identity, _ = provider.authenticate("Basic abc123")
    assert identity is None


def test_basic_auth_decodes_credentials():
    token = base64.b64encode(b"carol:carol_pw_123").decode()
    assert parse_basic_auth(f"Basic {token}") == ("carol", "carol_pw_123")


def test_basic_auth_rejects_non_basic():
    assert parse_basic_auth("Bearer abc") is None


def test_basic_auth_rejects_garbage():
    assert parse_basic_auth("Basic !!!not-base64!!!") is None
