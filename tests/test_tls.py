"""BL2-03: automated confirmation of TLS 1.3 negotiation on :8443."""
import socket
import ssl
import sys
sys.path.insert(0, "src")


def test_tls_version_is_1_3():
    ctx = ssl.create_default_context(cafile="certs/ca.crt")
    ctx.load_cert_chain(certfile="certs/client.crt", keyfile="certs/client.key")
    with socket.create_connection(("127.0.0.1", 8443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
            assert ssock.version() == "TLSv1.3"
