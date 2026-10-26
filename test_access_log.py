import sys, json
sys.path.insert(0, "src")
from proxy.access_log import setup_access_log, log_access

logger = setup_access_log("logs/test_access.jsonl")

log_access(logger, client_ip="127.0.0.1", method="GET", path="/api/data",
           identity="carol", role="admin", decision="allow",
           reason="LDAP OK, role=admin", duration_ms=12.4)

log_access(logger, client_ip="127.0.0.1", method="GET", path="/api/data?id=1'",
           identity="carol", role="admin", decision="400",
           reason="blocked by WAF (sql_injection)", duration_ms=1.1)

for h in logger.handlers:
    h.flush()

print("Contenu du fichier :")
with open("logs/test_access.jsonl") as f:
    for line in f:
        obj = json.loads(line)
        print(" ->", obj)
