"""BL5-03 — Unit tests for the Sprint 5 layers: WAF and structured logging.
No running services required.
"""
import json
import sys
import tempfile

import pytest

sys.path.insert(0, "src")

from proxy.config_loader import WAFConfig
from proxy.waf import WAF
from proxy.access_log import setup_access_log, log_access


class FakeRequest:
    def __init__(self, path, headers=None):
        self.path = path
        self.headers = headers or {}


# ============================================================ WAF
def make_waf():
    return WAF(WAFConfig(enabled=True, strip_headers=["x-forwarded-for"]))


def test_waf_allows_clean_request():
    ok, _ = make_waf().inspect(FakeRequest("/api/data"))
    assert ok is True


def test_waf_blocks_sql_injection():
    ok, reason = make_waf().inspect(FakeRequest("/api/data?id=1' OR '1'='1"))
    assert ok is False
    assert "sql_injection" in reason


def test_waf_blocks_xss():
    ok, reason = make_waf().inspect(FakeRequest("/search?q=<script>alert(1)</script>"))
    assert ok is False
    assert "xss" in reason


def test_waf_blocks_path_traversal():
    ok, reason = make_waf().inspect(FakeRequest("/files/../../etc/passwd"))
    assert ok is False
    assert "path_traversal" in reason


def test_waf_detects_attack_in_header_not_just_path():
    ok, _ = make_waf().inspect(
        FakeRequest("/api", {"x-custom": "<script>evil()</script>"}))
    assert ok is False


def test_waf_decodes_url_encoding_before_scanning():
    # regression test: an attack percent-encoded in the URL must still
    # be caught — this is the bypass that was found and fixed live.
    ok, reason = make_waf().inspect(FakeRequest("/api?id=1%27%20OR%20%271%27%3D%271"))
    assert ok is False
    assert "sql_injection" in reason


def test_waf_strips_configured_headers_only():
    waf = make_waf()
    cleaned = waf.sanitize_headers({
        "Host": "x", "X-Forwarded-For": "1.2.3.4", "Authorization": "Bearer abc"
    })
    assert "X-Forwarded-For" not in cleaned
    assert cleaned["Authorization"] == "Bearer abc"


def test_waf_disabled_allows_everything():
    waf = WAF(WAFConfig(enabled=False, strip_headers=[]))
    ok, reason = waf.inspect(FakeRequest("/api?id=1' OR '1'='1"))
    assert ok is True
    assert "disabled" in reason.lower()


# ============================================================ ACCESS LOG
def test_access_log_writes_valid_json():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name
    logger = setup_access_log(path)
    log_access(logger, client_ip="10.0.0.1", method="GET", path="/x",
               identity="alice", role="user", decision="allow",
               reason="ok", duration_ms=5.0)
    for h in logger.handlers:
        h.flush()

    with open(path) as f:
        lines = f.readlines()
    assert len(lines) == 1
    record = json.loads(lines[0])  # must not raise
    assert record["identity"] == "alice"
    assert record["decision"] == "allow"


def test_access_log_one_line_per_call():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name
    logger = setup_access_log(path)
    for i in range(3):
        log_access(logger, client_ip="10.0.0.1", method="GET", path=f"/{i}",
                   identity=None, role=None, decision="allow",
                   reason="ok", duration_ms=1.0)
    for h in logger.handlers:
        h.flush()

    with open(path) as f:
        lines = f.readlines()
    assert len(lines) == 3
    for line in lines:
        json.loads(line)  # every line independently valid
