"""BL4-04 — Unit tests for the Sprint 4 access-control layers:
IP filtering, RBAC, and rate limiting. No running services required.
"""
import sys
import time

import pytest

sys.path.insert(0, "src")

from proxy.config_loader import (
    load_config, IPFilterConfig, RBACConfig, RateLimitConfig,
)
from proxy.ip_filter import IPFilter
from proxy.rbac import RBAC
from proxy.rate_limiter import RateLimiter


# ============================================================ IP FILTER
def make_ip_filter():
    cfg = IPFilterConfig(
        enabled=True,
        whitelist=[],
        blacklist=["192.0.2.0/24", "203.0.113.66/32"],
    )
    return IPFilter(cfg)


def test_ip_allowed_when_not_listed():
    ok, _ = make_ip_filter().is_allowed("127.0.0.1")
    assert ok is True


def test_ip_blocked_by_range():
    ok, reason = make_ip_filter().is_allowed("192.0.2.55")
    assert ok is False
    assert "blacklist" in reason.lower()


def test_ip_blocked_single_address():
    ok, _ = make_ip_filter().is_allowed("203.0.113.66")
    assert ok is False


def test_ip_neighbour_of_blocked_is_allowed():
    # .67 must pass even though .66/32 is blocked — proves the mask is exact
    ok, _ = make_ip_filter().is_allowed("203.0.113.67")
    assert ok is True


def test_ip_invalid_address_is_refused():
    ok, _ = make_ip_filter().is_allowed("not-an-ip")
    assert ok is False


def test_ip_whitelist_only_allows_listed():
    cfg = IPFilterConfig(enabled=True, whitelist=["10.0.0.0/24"], blacklist=[])
    f = IPFilter(cfg)
    assert f.is_allowed("10.0.0.5")[0] is True
    assert f.is_allowed("8.8.8.8")[0] is False


# ============================================================ RBAC
def make_rbac():
    cfg = RBACConfig(
        enabled=True,
        roles={
            "admin": ["GET", "POST", "PUT", "DELETE"],
            "user": ["GET", "POST"],
            "device": ["GET"],
            "guest": [],
        },
        default_roles={"certificate": "device", "jwt": "user", "unknown": "guest"},
    )
    return RBAC(cfg)


def test_rbac_admin_can_delete():
    assert make_rbac().is_allowed("admin", "DELETE")[0] is True


def test_rbac_user_cannot_delete():
    assert make_rbac().is_allowed("user", "DELETE")[0] is False


def test_rbac_user_can_get():
    assert make_rbac().is_allowed("user", "GET")[0] is True


def test_rbac_device_only_reads():
    r = make_rbac()
    assert r.is_allowed("device", "GET")[0] is True
    assert r.is_allowed("device", "POST")[0] is False


def test_rbac_guest_can_do_nothing():
    assert make_rbac().is_allowed("guest", "GET")[0] is False


def test_rbac_unknown_role_denied():
    assert make_rbac().is_allowed("wizard", "GET")[0] is False


def test_rbac_role_mapping():
    r = make_rbac()
    assert r.role_for("ldap", ldap_role="admin") == "admin"
    assert r.role_for("certificate") == "device"
    assert r.role_for("jwt") == "user"


# ============================================================ RATE LIMITER
def make_limiter(quota=3, window=2):
    cfg = RateLimitConfig(
        enabled=True, window_seconds=window,
        quotas={"device": quota}, default_quota=quota,
    )
    return RateLimiter(cfg)


def test_rate_allows_up_to_quota():
    rl = make_limiter(quota=3)
    for _ in range(3):
        assert rl.check("10.0.0.1", "device")[0] is True


def test_rate_blocks_over_quota():
    rl = make_limiter(quota=3)
    for _ in range(3):
        rl.check("10.0.0.1", "device")
    ok, reason, retry = rl.check("10.0.0.1", "device")
    assert ok is False
    assert retry > 0


def test_rate_separate_ips_independent():
    rl = make_limiter(quota=2)
    rl.check("10.0.0.1", "device")
    rl.check("10.0.0.1", "device")
    # second IP still has its full quota
    assert rl.check("10.0.0.2", "device")[0] is True


def test_rate_window_slides():
    rl = make_limiter(quota=2, window=1)
    rl.check("10.0.0.1", "device")
    rl.check("10.0.0.1", "device")
    assert rl.check("10.0.0.1", "device")[0] is False
    time.sleep(1.1)  # window passes
    assert rl.check("10.0.0.1", "device")[0] is True
