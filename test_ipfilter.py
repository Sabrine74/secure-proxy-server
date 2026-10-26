import sys
sys.path.insert(0, "src")
from proxy.config_loader import load_config
from proxy.ip_filter import IPFilter

f = IPFilter(load_config("config/policies.yaml").ip_filter)

print("1. localhost (allowed)     ->", f.is_allowed("127.0.0.1"))
print("2. blacklisted /24         ->", f.is_allowed("192.0.2.55"))
print("3. blacklisted single IP   ->", f.is_allowed("203.0.113.66"))
print("4. neighbour of blacklist  ->", f.is_allowed("203.0.113.67"))
print("5. garbage address         ->", f.is_allowed("not-an-ip"))
