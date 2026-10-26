"""Proxy relay: TLS termination + HTTP parsing + authentication, then forward."""
from __future__ import annotations
import asyncio
import logging
import time

from .config_loader import ProxyConfig
from .tls_manager import TLSManager
from .http_parser import read_request
from .oauth2_provider import OAuth2Provider
from .ldap_provider import LDAPProvider
from .ip_filter import IPFilter
from .rbac import RBAC
from .rate_limiter import RateLimiter
from .waf import WAF
from .access_log import setup_access_log, log_access

BUFFER_SIZE = 65536


class TcpRelay:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.log = logging.getLogger("secure_proxy")
        self.tls = TLSManager(config)
        self.oauth2 = OAuth2Provider(config.oauth2)
        self.ldap = LDAPProvider(config.ldap)
        self.ip_filter = IPFilter(config.ip_filter)
        self.rbac = RBAC(config.rbac)
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.waf = WAF(config.waf)
        self.access_logger = setup_access_log()

    async def _pump(self, reader, writer) -> int:
        total = 0
        try:
            while True:
                chunk = await reader.read(BUFFER_SIZE)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
                total += len(chunk)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
        return total

    async def _deny(self, writer, code, reason, extra_headers=None):
        try:
            body = f'{{"error": "{reason}"}}'.encode()
            head = f"HTTP/1.1 {code}\r\nContent-Type: application/json\r\n"
            head += f"Content-Length: {len(body)}\r\nConnection: close\r\n"
            for k, v in (extra_headers or {}).items():
                head += f"{k}: {v}\r\n"
            resp = (head + "\r\n").encode() + body
            writer.write(resp)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _authenticate(self, request, cert_identity):
        """Precedence: JWT (Bearer) > LDAP (Basic) > mTLS certificate.

        Returns (identity, source, ldap_role, reason). `source` and `ldap_role`
        feed RBAC.role_for() afterwards; ldap_role is None unless LDAP resolved
        one from group membership.
        """
        auth = request.header("Authorization")
        if auth:
            scheme = auth.split(None, 1)[0].lower()
            if scheme == "bearer":
                identity, reason = self.oauth2.authenticate(auth)
                if identity:
                    return identity, "jwt", None, f"JWT: {reason}"
                return None, None, None, f"JWT rejected ({reason})"
            if scheme == "basic":
                identity, role, reason = self.ldap.authenticate(auth)
                if identity:
                    return identity, "ldap", role, f"LDAP: {reason}"
                return None, None, None, f"LDAP rejected ({reason})"
            return None, None, None, f"unsupported auth scheme: {scheme}"
        if cert_identity:
            return cert_identity, "certificate", None, "mTLS certificate"
        return None, None, None, "no credentials"

    async def _handle_client(self, client_reader, client_writer) -> None:
        peer = client_writer.get_extra_info("peername") or ("?", 0)
        client_ip = peer[0]
        ssl_object = client_writer.get_extra_info("ssl_object")
        # ---- LAYER 1 - TLS / mTLS (handshake already enforced by ssl module) ----
        cert_identity = TLSManager.peer_common_name(ssl_object)

        start = time.monotonic()
        # State written by whichever stage decides the outcome; read by the
        # `finally` block below so exactly one JSON access-log line is
        # written per request, no matter which layer ended it.
        state = {
            "method": "-", "path": "-", "identity": None, "role": None,
            "decision": "allow", "reason": "unknown",
        }

        try:
            # ---- LAYER 2 - IP filter (before parsing, before auth) ----
            allowed, ip_reason = self.ip_filter.is_allowed(client_ip)
            if not allowed:
                state["decision"], state["reason"] = "403", ip_reason
                self.log.info("%s -> 403 (%s)", client_ip, ip_reason)
                await self._deny(client_writer, "403 Forbidden", ip_reason)
                return
            # ---- LAYER 3 - HTTP parsing ----

            try:
                request = await asyncio.wait_for(
                    read_request(client_reader), timeout=self.config.request_timeout)
            except asyncio.TimeoutError:
                state["decision"], state["reason"] = "408", "client too slow"
                await self._deny(client_writer, "408 Request Timeout", "client too slow")
                self.log.info("%s -> 408 (timeout)", client_ip)
                return
            except Exception as exc:
                state["decision"], state["reason"] = "500", str(exc)
                await self._deny(client_writer, "500 Internal Server Error", "parser error")
                self.log.error("%s -> 500 (%s)", client_ip, exc)
                return

            if request is None:
                state["decision"], state["reason"] = "400", "malformed request"
                await self._deny(client_writer, "400 Bad Request", "malformed request")
                self.log.info("%s -> 400 (malformed)", client_ip)
                return

            state["method"], state["path"] = request.method, request.path
            # ---- LAYER 4 - Authentication (JWT > LDAP > mTLS certificate) ----

            identity, source, ldap_role, reason = self._authenticate(request, cert_identity)
            if identity is None:
                state["decision"], state["reason"] = "401", reason
                await self._deny(client_writer, "401 Unauthorized", reason)
                self.log.info("%s %s %s -> 401 (%s)", client_ip, request.method, request.path, reason)
                return
            state["identity"] = identity

            # ---- LAYER 5 - RBAC (role x method authorization) ----
            role = self.rbac.role_for(source, ldap_role)
            state["role"] = role
            rbac_allowed, rbac_reason = self.rbac.is_allowed(role, request.method)
            if not rbac_allowed:
                state["decision"], state["reason"] = "403", rbac_reason
                await self._deny(client_writer, "403 Forbidden", rbac_reason)
                self.log.info("%s %s %s -> 403 as %s, role %s (%s)",
                              client_ip, request.method, request.path, identity, role, rbac_reason)
                return

            # ---- LAYER 6 - Rate limiting (after RBAC) ----
            ok_rate, rate_reason, retry_after = self.rate_limiter.check(client_ip, role)
            if not ok_rate:
                state["decision"], state["reason"] = "429", rate_reason
                await self._deny(client_writer, "429 Too Many Requests", rate_reason,
                                 extra_headers={"Retry-After": str(retry_after)})
                self.log.info("%s %s %s -> 429 as %s, role %s (%s)",
                              client_ip, request.method, request.path, identity, role, rate_reason)
                return

            # ---- LAYER 7 - WAF (scan content, right before forwarding) ----
            waf_allowed, waf_reason = self.waf.inspect(request)
            if not waf_allowed:
                state["decision"], state["reason"] = "400", waf_reason
                await self._deny(client_writer, "400 Bad Request", waf_reason)
                self.log.info("%s %s %s -> 400 as %s, role %s (%s)",
                              client_ip, request.method, request.path, identity, role, waf_reason)
                return
            request.headers = self.waf.sanitize_headers(request.headers)

            state["decision"], state["reason"] = "allow", reason
            self.log.info("%s %s %s -> authenticated as %s, role %s (%s)",
                          client_ip, request.method, request.path, identity, role, reason)

            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.upstream_host, self.config.upstream_port),
                    timeout=self.config.request_timeout)
            except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                state["decision"], state["reason"] = "502", "backend unreachable"
                await self._deny(client_writer, "502 Bad Gateway", "backend unreachable")
                self.log.error("Backend unreachable: %s", exc)
                return

            try:
                up_writer.write(request.raw_head)
                await up_writer.drain()
            except (ConnectionError, OSError) as exc:
                state["decision"], state["reason"] = "502", "failed writing to backend"
                self.log.error("Failed writing to backend: %s", exc)
                up_writer.close()
                return

            sent, received = await asyncio.gather(
                self._pump(client_reader, up_writer),
                self._pump(up_reader, client_writer),
            )
            self.log.info("%s (%s) done: %d sent, %d received", client_ip, identity, sent, received)

        finally:
            duration_ms = (time.monotonic() - start) * 1000
            log_access(
                self.access_logger, client_ip=client_ip,
                method=state["method"], path=state["path"],
                identity=state["identity"], role=state["role"],
                decision=state["decision"], reason=state["reason"],
                duration_ms=duration_ms,
            )

    async def start(self):
        ssl_context = self.tls.server_context()
        server = await asyncio.start_server(
            self._handle_client, host=self.config.listen_host,
            port=self.config.listen_port, ssl=ssl_context)
        mode = "mTLS" if self.config.tls.mutual_tls else "TLS"
        self.log.info("Relay listening on %s:%d (%s) -> backend %s:%d",
                      self.config.listen_host, self.config.listen_port, mode,
                      self.config.upstream_host, self.config.upstream_port)
        return server
