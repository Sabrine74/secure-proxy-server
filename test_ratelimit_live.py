import subprocess, base64

CA, CRT, KEY = "certs/ca.crt", "certs/client.crt", "certs/client.key"
URL = "https://127.0.0.1:8443/api/data"
carol = base64.b64encode(b"carol:carol_pw_123").decode()

for i in range(1, 9):
    r = subprocess.run(
        ["curl", "-sk", URL, "--cacert", CA, "--cert", CRT, "--key", KEY,
         "-H", f"Authorization: Basic {carol}"],
        capture_output=True, text=True)
    print(f"req {i}: {r.stdout.strip()[:75]}")
