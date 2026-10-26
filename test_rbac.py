import sys
sys.path.insert(0, "src")
from proxy.config_loader import load_config
from proxy.rbac import RBAC

r = RBAC(load_config("config/policies.yaml").rbac)

print("1. admin  + DELETE ->", r.is_allowed("admin", "DELETE"))
print("2. user   + DELETE ->", r.is_allowed("user", "DELETE"))
print("3. user   + GET    ->", r.is_allowed("user", "GET"))
print("4. device + GET    ->", r.is_allowed("device", "GET"))
print("5. device + POST   ->", r.is_allowed("device", "POST"))
print("6. guest  + GET    ->", r.is_allowed("guest", "GET"))
print("7. unknown role    ->", r.is_allowed("wizard", "GET"))
print()
print("role from LDAP     ->", r.role_for("ldap", ldap_role="admin"))
print("role from cert     ->", r.role_for("certificate"))
print("role from jwt      ->", r.role_for("jwt"))
