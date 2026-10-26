import sys
sys.path.insert(0, "src")
from proxy.config_loader import load_config
from proxy.waf import WAF

class FakeRequest:
    def __init__(self, path, headers=None):
        self.path = path
        self.headers = headers or {}

waf = WAF(load_config("config/policies.yaml").waf)

print("1. clean request        ->", waf.inspect(FakeRequest("/api/data")))
print("2. SQL injection in path->", waf.inspect(FakeRequest("/api/data?id=1' OR '1'='1")))
print("3. UNION SELECT         ->", waf.inspect(FakeRequest("/api?q=1 UNION SELECT password")))
print("4. XSS in path          ->", waf.inspect(FakeRequest("/search?q=<script>alert(1)</script>")))
print("5. path traversal       ->", waf.inspect(FakeRequest("/files/../../etc/passwd")))
print("6. clean header         ->", waf.inspect(FakeRequest("/api", {"user-agent": "curl/8.5"})))
print("7. attack in header     ->", waf.inspect(FakeRequest("/api", {"x-custom": "<script>evil()</script>"})))
print()
print("8. strip headers        ->", waf.sanitize_headers({
    "Host": "x", "X-Forwarded-For": "1.2.3.4", "Authorization": "Bearer abc"
}))
