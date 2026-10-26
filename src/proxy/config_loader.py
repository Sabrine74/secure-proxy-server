"""Load and validate the proxy configuration from a YAML file."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import yaml


@dataclasses.dataclass
class TLSConfig:
    cert_file: str
    key_file: str
    ca_file: str
    mutual_tls: bool


@dataclasses.dataclass
class OAuth2Config:
    enabled: bool
    secret: str
    issuer: str
    audience: str


@dataclasses.dataclass
class LDAPConfig:
    enabled: bool
    server: str
    base_dn: str
    user_dn_template: str
    group_base_dn: str
    group_role_map: dict[str, str]


@dataclasses.dataclass
class IPFilterConfig:
    enabled: bool
    whitelist: list[str]
    blacklist: list[str]


@dataclasses.dataclass
class RBACConfig:
    enabled: bool
    roles: dict[str, list[str]]
    default_roles: dict[str, str]


@dataclasses.dataclass
class RateLimitConfig:
    enabled: bool
    window_seconds: int
    quotas: dict[str, int]
    default_quota: int


@dataclasses.dataclass
class WAFConfig:
    enabled: bool
    strip_headers: list[str]


@dataclasses.dataclass
class ProxyConfig:
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    health_port: int
    request_timeout: int
    tls: TLSConfig
    oauth2: OAuth2Config
    ldap: LDAPConfig
    ip_filter: IPFilterConfig
    rbac: RBACConfig
    rate_limit: RateLimitConfig
    waf: WAFConfig


REQUIRED_PROXY_KEYS = ["listen_host", "listen_port", "upstream_host", "upstream_port"]


def load_config(path: str | Path) -> ProxyConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    proxy = raw.get("proxy", {})
    missing = [k for k in REQUIRED_PROXY_KEYS if k not in proxy]
    if missing:
        raise ValueError(f"Missing required config keys under 'proxy': {missing}")

    tls = raw["tls"]
    oauth = raw["authentication"]["oauth2"]
    ldap = raw["authentication"].get("ldap", {})
    ipf = raw.get("ip_filter", {})
    rb = raw.get("rbac", {})
    rl = raw.get("rate_limiting", {})
    wf = raw.get("waf", {})

    return ProxyConfig(
        listen_host=proxy["listen_host"],
        listen_port=int(proxy["listen_port"]),
        upstream_host=proxy["upstream_host"],
        upstream_port=int(proxy["upstream_port"]),
        health_port=int(proxy.get("health_port", 8080)),
        request_timeout=int(proxy.get("request_timeout", 10)),
        tls=TLSConfig(
            cert_file=tls["cert_file"],
            key_file=tls["key_file"],
            ca_file=tls["ca_file"],
            mutual_tls=bool(tls["mutual_tls"]),
        ),
        oauth2=OAuth2Config(
            enabled=bool(oauth["enabled"]),
            secret=oauth["secret"],
            issuer=oauth["issuer"],
            audience=oauth["audience"],
        ),
        ldap=LDAPConfig(
            enabled=bool(ldap.get("enabled", False)),
            server=ldap.get("server", ""),
            base_dn=ldap.get("base_dn", ""),
            user_dn_template=ldap.get("user_dn_template", ""),
            group_base_dn=ldap.get("group_base_dn", ""),
            group_role_map=ldap.get("group_role_map", {}),
        ),
        ip_filter=IPFilterConfig(
            enabled=bool(ipf.get("enabled", False)),
            whitelist=list(ipf.get("whitelist") or []),
            blacklist=list(ipf.get("blacklist") or []),
        ),
        rbac=RBACConfig(
            enabled=bool(rb.get("enabled", False)),
            roles=rb.get("roles", {}),
            default_roles=rb.get("default_roles", {}),
        ),
        rate_limit=RateLimitConfig(
            enabled=bool(rl.get("enabled", False)),
            window_seconds=int(rl.get("window_seconds", 60)),
            quotas=rl.get("quotas", {}),
            default_quota=int(rl.get("default_quota", 20)),
        ),
        waf=WAFConfig(
            enabled=bool(wf.get("enabled", False)),
            strip_headers=list(wf.get("strip_headers") or []),
        ),
    )
