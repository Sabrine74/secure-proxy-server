import subprocess, sys, time
sys.path.insert(0, "src")
import jwt
from proxy.config_loader import load_config

c = load_config("config/policies.yaml").oauth2
tok = jwt.encode({"sub": "alice", "iss": c.issuer, "aud": c.audience,
                   "exp": int(time.time()) + 3600}, c.secret, algorithm="HS256")

r = subprocess.run(
    ["curl", "-sk", "https://127.0.0.1:8443/api/data",
     "--cacert", "certs/ca.crt", "--cert", "certs/client.crt", "--key", "certs/client.key",
     "-H", f"Authorization: Bearer {tok}"],
    capture_output=True, text=True)
print("STDOUT:", r.stdout)
print("STDERR:", r.stderr)
