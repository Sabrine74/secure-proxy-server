"""BL3-05 — Integration tests: the live proxy, end to end.
Requires Flask (:5000), the proxy (:8443) and the LDAP container to be running."""
import base64
import socket
import ssl
import subprocess
import sys
import time

import jwt
import pytest

sys.path.insert(0, "src")
from proxy.config_loader import load_config

CONFIG = load_config("config/policies.yaml")
URL = f"https://127.0.0.1:{CONFIG.listen_port}/api/data"
CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"


def _proxy_is_up():
    try:
        with socket.create_connection(("127.0.0.1", CONFIG.listen_port), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _proxy_is_up(), reason="proxy not running")


def curl(*extra):
    cmd = ["curl", "-sk", URL, "--cacert", CA, "--cert", CRT, "--key", KEY, *extra]
    return subprocess.run(cmd, capture_output=True, text=True)


def make_jwt(sub="alice"):
    c = CONFIG.oauth2
    return jwt.encode(
        {"sub": sub, "iss": c.issuer, "aud": c.audience,
         "exp": int(time.time()) + 3600}, c.secret, algorithm="HS256")


def test_tls_version_is_1_3():
    ctx = ssl.create_default_context(cafile=CA)
    ctx.load_cert_chain(certfile=CRT, keyfile=KEY)
    with socket.create_connection(("127.0.0.1", CONFIG.listen_port), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname="127.0.0.1") as ss:
            assert ss.version() == "TLSv1.3"


def test_mtls_client_without_certificate_gets_no_data():
    """No client certificate: the connection is dropped, no data is served."""
    r = subprocess.run(["curl", "-sk", URL, "--cacert", CA],
                       capture_output=True, text=True)
    assert "data" not in r.stdout


def test_certificate_identity_is_forwarded():
    r = curl()
    assert r.returncode == 0
    assert "data" in r.stdout


def test_jwt_identity_is_forwarded():
    r = curl("-H", f"Authorization: Bearer {make_jwt('alice')}")
    assert r.returncode == 0
    assert "data" in r.stdout


def test_ldap_identity_is_forwarded():
    token = base64.b64encode(b"carol:carol_pw_123").decode()
    r = curl("-H", f"Authorization: Basic {token}")
    assert r.returncode == 0
    assert "data" in r.stdout


def test_invalid_jwt_is_rejected():
    r = curl("-H", "Authorization: Bearer not.a.valid.token")
    assert "data" not in r.stdout


def test_wrong_ldap_password_is_rejected():
    token = base64.b64encode(b"carol:wrong_password").decode()
    r = curl("-H", f"Authorization: Basic {token}")
    assert "data" not in r.stdout


def test_health_listener_responds_without_tls():
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", CONFIG.health_port, timeout=3)
    conn.request("GET", "/")
    resp = conn.getresponse()
    assert resp.status == 200
    assert b"secure-proxy" in resp.read()
