import subprocess, base64

token = base64.b64encode(b"carol:carol_pw_123").decode()
r = subprocess.run(
    ["curl", "-sk", "https://127.0.0.1:8443/api/data",
     "--cacert", "certs/ca.crt", "--cert", "certs/client.crt", "--key", "certs/client.key",
     "-H", f"Authorization: Basic {token}"],
    capture_output=True, text=True)
print("STDOUT:", r.stdout)
print("STDERR:", r.stderr)
