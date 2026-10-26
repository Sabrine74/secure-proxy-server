import sys
sys.path.insert(0, "src")
from ldap3 import Server, Connection, ALL, SUBTREE
from proxy.config_loader import load_config

cfg = load_config("config/policies.yaml").ldap
user_dn = cfg.user_dn_template.format(username="carol")

server = Server(cfg.server, get_info=ALL)
conn = Connection(server, user=user_dn, password="carol_pw_123")
print("bind success:", conn.bind())

conn.search(
    search_base=cfg.group_base_dn,
    search_filter=f"(member={user_dn})",
    search_scope=SUBTREE,
    attributes=["cn"],
)
print("group_base_dn used:", cfg.group_base_dn)
print("user_dn used in filter:", user_dn)
print("entries found:", conn.entries)
for e in conn.entries:
    print(" -> cn:", str(e.cn))
