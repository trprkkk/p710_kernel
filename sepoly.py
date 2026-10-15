import re, sys
p = r"Q:\Downloads\P710\plat_sepolicy.cil"
v = r"Q:\Downloads\P710\vendor_sepolicy.cil"

def load(p):
    return open(p, "r", errors="ignore").read().splitlines()

plat = load(p) + load(v)

# find typeattributes for appdomain-ish base typeattr
attr_of = {}
for ln in plat:
    m = re.match(r"\(typeattributeset (base_typeattr_\d+) \(and \(appdomain \) \(not \(isolated_app \)\)\)\)", ln)
    if m:
        attr_of["untrusted_base"] = m.group(1)
print("attrs:", attr_of)

targets = set()
for ln in plat:
    m = re.match(r"\(allow (base_typeattr_\d+|appdomain|untrusted_app|domain) (\S+) \(chr_file \(([^)]+)\)\)\)", ln)
    if m:
        targets.add((m.group(1), m.group(2), m.group(3)))
for t in sorted(targets):
    print(t)

