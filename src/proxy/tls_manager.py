"""Builds the SSL context used to terminate TLS (and later enforce mTLS)."""
from __future__ import annotations

import ssl

from .config_loader import ProxyConfig


class TLSManager:
    def __init__(self, config: ProxyConfig):
        self.config = config

    def server_context(self) -> ssl.SSLContext:
        """Create the TLS context the proxy presents to clients."""
        cfg = self.config
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load the proxy's own certificate and private key
        ctx.load_cert_chain(certfile=cfg.tls.cert_file, keyfile=cfg.tls.key_file)

        # Mutual TLS: require and verify the client's certificate
        if cfg.tls.mutual_tls:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=cfg.tls.ca_file)

        return ctx

    @staticmethod
    def peer_common_name(ssl_object) -> str | None:
        """Extract the Common Name (CN) from the client certificate, if any."""
        if ssl_object is None:
            return None
        cert = ssl_object.getpeercert()
        if not cert:
            return None
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return None
