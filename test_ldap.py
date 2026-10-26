import sys, base64
sys.path.insert(0, "src")
from proxy.config_loader import load_config
from proxy.ldap_provider import LDAPProvider

cfg = load_config("config/policies.yaml").ldap
provider = LDAPProvider(cfg)

def basic_header(user, pw):
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {token}"

print("1. valid carol        -> identity=%s role=%s reason=%s" % provider.authenticate(basic_header("carol", "carol_pw_123")))
print("2. wrong password     -> identity=%s role=%s reason=%s" % provider.authenticate(basic_header("carol", "wrong")))
print("3. unknown user       -> identity=%s role=%s reason=%s" % provider.authenticate(basic_header("mallory", "whatever")))
print("4. no header          -> identity=%s role=%s reason=%s" % provider.authenticate(None))
