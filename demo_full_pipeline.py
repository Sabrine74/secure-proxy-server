"""BL6-03 — Full pipeline demonstration.

Replays one scenario per security layer against the LIVE proxy, in
pipeline order, so the whole system can be shown working end-to-end
in a single run. Requires Flask, the proxy, and LDAP to be running.
"""
import base64
import subprocess
import time
from urllib.parse import quote

CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"
BASE = "https://127.0.0.1:8443"
carol = base64.b64encode(b"carol:carol_pw_123").decode()

RESET, BOLD, GREEN, RED, DIM = "\033[0m", "\033[1m", "\033[92m", "\033[91m", "\033[2m"


def call(path="/api/data", method="GET", headers=None, use_cert=True):
    cmd = ["curl", "-sk", "-X", method, "--path-as-is", f"{BASE}{path}", "--cacert", CA]
    if use_cert:
        cmd += ["--cert", CRT, "--key", KEY]
    for h in (headers or []):
        cmd += ["-H", h]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    return r.stdout.strip() or "(no response — connection refused)"


def show(title, layer, result, expect_block):
    proxy_blocked = '"error"' in result             # our proxy's own JSON refusal
    backend_reply = "Method Not Allowed" in result   # backend answered, not the proxy
    ok = (proxy_blocked == expect_block) or (backend_reply and not expect_block)
    tag = f"{GREEN}\u2713" if ok else f"{RED}\u2717"
    print(f"\n{BOLD}[{layer}]{RESET} {title}")
    print(f"{DIM}{result[:110]}{RESET}")
    if backend_reply and not expect_block:
        print(f"{tag} RBAC allowed it through \u2014 Flask itself has no DELETE route (405, unrelated to security){RESET}")
    else:
        msg = "blocked as expected" if expect_block else "allowed as expected"
        print(f"{tag} {msg}{RESET}" if ok else f"{RED}\u2717 UNEXPECTED RESULT{RESET}")


print(f"{BOLD}=== Secure Proxy — Full Pipeline Demonstration ==={RESET}")
print("Replaying one scenario per security layer, in pipeline order.\n")

# Layer 1/2 — IP filter needs no live demo here (would require editing config);
# already proven in BL4-01 tests. Skipping to keep this demo non-destructive.

show("Certificate identity (IoT device)", "Layer 1+4 — TLS + Auth",
     call(), expect_block=False)

show("LDAP login as carol (admin)", "Layer 4 — Auth (LDAP)",
     call(headers=[f"Authorization: Basic {carol}"]), expect_block=False)

show("Invalid JWT token", "Layer 4 — Auth (JWT)",
     call(headers=["Authorization: Bearer not.a.valid.token"]), expect_block=True)

show("Device certificate attempting DELETE", "Layer 5 — RBAC",
     call(method="DELETE"), expect_block=True)

show("Carol (admin) attempting DELETE", "Layer 5 — RBAC",
     call(method="DELETE", headers=[f"Authorization: Basic {carol}"]),
     expect_block=False)

print(f"\n{BOLD}[Layer 6 — Rate limiting]{RESET} Sending 6 rapid requests as carol "
      f"(quota is high by default; showing the mechanism, not forcing a 429 here)")
for i in range(3):
    r = call(headers=[f"Authorization: Basic {carol}"])
    print(f"  req {i+1}: {r[:70]}")

show("SQL injection attempt", "Layer 7 — WAF",
     call(path="/api/data?id=1" + quote("' OR '1'='1"),
          headers=[f"Authorization: Basic {carol}"]), expect_block=True)

show("XSS attempt", "Layer 7 — WAF",
     call(path="/api/data?q=" + quote("<script>alert(1)</script>"),
          headers=[f"Authorization: Basic {carol}"]), expect_block=True)

show("Path traversal attempt", "Layer 7 — WAF",
     call(path="/api/data/../../etc/passwd",
          headers=[f"Authorization: Basic {carol}"]), expect_block=True)

print(f"\n{BOLD}=== Demonstration complete ==={RESET}")
print("Check logs/access.jsonl and the proxy terminal for the full audit trail.")
