import sys, time
sys.path.insert(0, "src")
from proxy.config_loader import load_config, RateLimitConfig
from proxy.rate_limiter import RateLimiter

# small quota so the test is fast: 3 requests / 2 s window
cfg = RateLimitConfig(enabled=True, window_seconds=2,
                      quotas={"device": 3}, default_quota=3)
rl = RateLimiter(cfg)

print("3 premières requêtes (quota=3) :")
for i in range(3):
    print(f"  req {i+1} ->", rl.check("10.0.0.1", "device"))

print("4e requête (dépasse) :")
print("  ->", rl.check("10.0.0.1", "device"))

print("Autre IP, pas affectée :")
print("  ->", rl.check("10.0.0.2", "device"))

print("On attend 2,1 s que la fenêtre glisse...")
time.sleep(2.1)
print("Nouvelle requête après la fenêtre :")
print("  ->", rl.check("10.0.0.1", "device"))
