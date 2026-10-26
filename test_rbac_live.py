import subprocess, base64

CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"
URL = "https://127.0.0.1:8443/api/data"
carol = base64.b64encode(b"carol:carol_pw_123").decode()

def call(method, extra=None):
    cmd = ["curl", "-sk", "-X", method, URL, "--cacert", CA,
           "--cert", CRT, "--key", KEY]
    if extra:
        cmd += extra
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()[:90]

print("1. carol (admin) GET    ->", call("GET",    ["-H", f"Authorization: Basic {carol}"]))
print("2. carol (admin) DELETE ->", call("DELETE", ["-H", f"Authorization: Basic {carol}"]))
print("3. cert  (device) GET   ->", call("GET"))
print("4. cert  (device) DELETE->", call("DELETE"))
