import subprocess, base64
from urllib.parse import quote

CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"
carol = base64.b64encode(b"carol:carol_pw_123").decode()

def call(path):
    url = f"https://127.0.0.1:8443{path}"
    r = subprocess.run(
        ["curl", "-sk", "--path-as-is", url, "--cacert", CA,
         "--cert", CRT, "--key", KEY,
         "-H", f"Authorization: Basic {carol}"],
        capture_output=True, text=True)
    return (r.stdout.strip() or f"[stderr: {r.stderr.strip()}]")[:110]

print("1. requête propre        ->", call("/api/data"))
print("2. injection SQL         ->", call("/api/data?id=1" + quote("' OR '1'='1")))
print("3. XSS                   ->", call("/api/data?q=" + quote("<script>alert(1)</script>")))
print("4. traversée de dossier  ->", call("/api/data/../../etc/passwd"))
