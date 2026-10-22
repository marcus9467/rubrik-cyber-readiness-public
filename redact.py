"""Pseudonymize identifying values in a bundle so it can be shared outside the customer.

What is replaced: user ids and emails, service account names and client ids, IP allowlist entries,
object / host / cluster / SLA / account names, and anything else that names a customer asset.
What is kept on purpose, because scoring needs it: counts, booleans, dates, domains (LOCAL/SSO),
role names, object types, and RSC's own score metrics.

Pseudonyms are `<kind>-<8 hex>` derived from a random per-run salt, so the same value maps to the same
pseudonym within one bundle but cannot be reversed without the salt. The salt-keyed map is written to
a separate file that stays with the customer.
"""
import copy
import hashlib
import json
import os
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


# Built-in RSC role names carry no customer information and scoring matches on two of them.
# Every other role name is a customer choice and is pseudonymized.
BUILTIN_ROLES = {"Administrator", "Owner", "Read-only Administrator", "QAuth Admin", "QAuth Approver"}


def _role(ps, role):
    if isinstance(role, dict) and "name" in role and role["name"] not in BUILTIN_ROLES:
        role["name"] = ps("role", role["name"])
    if isinstance(role, dict) and role.get("description"):
        role["description"] = "withheld by redaction"
    if isinstance(role, dict) and "id" in role:
        role["id"] = ps("role", role["id"])


class Pseudonymizer:
    def __init__(self, salt=None):
        self.salt = salt or os.urandom(16).hex()
        self.map = {}

    def __call__(self, kind, value):
        if value in (None, ""):
            return value
        value = str(value)
        key = f"{kind}:{value}"
        if key not in self.map:
            digest = hashlib.sha256(f"{self.salt}|{key}".encode()).hexdigest()[:8]
            self.map[key] = f"{kind}-{digest}"
        return self.map[key]


def _scrub_free_text(text, ps):
    """Replace any email address that appears inside a longer string."""
    return EMAIL_RE.sub(lambda m: ps("email", m.group(0)), text) if isinstance(text, str) else text


def redact_bundle(bundle):
    """Return (redacted_bundle, mapping). The input is not modified."""
    ps = Pseudonymizer()
    b = copy.deepcopy(bundle)
    d = b["data"]

    # Identity
    for u in d.get("identity", {}).get("users", []) or []:
        u["id"] = ps("user", u.get("id"))
        u["email"] = ps("email", u.get("email"))
        if "username" in u:
            u["username"] = ps("user", u["username"])
        for r in u.get("roles", []) or []:
            _role(ps, r)

    # Access
    a = d.get("access", {})
    if isinstance(a.get("serviceAccounts"), list):
        for s in a["serviceAccounts"]:
            s["name"] = ps("svc", s.get("name"))
            s["clientId"] = ps("client", s.get("clientId"))
            for r in s.get("roles", []) or []:
                _role(ps, r)
    if isinstance(a.get("roles"), list):
        for r in a["roles"]:
            _role(ps, r)
    # SSO groups: group names, ids and the IdP domain are customer data; role names go through _role.
    if isinstance(a.get("ssoGroups"), list):
        for g in a["ssoGroups"]:
            g["groupId"] = ps("group", g.get("groupId"))
            g["groupName"] = ps("group", g.get("groupName"))
            g["domainName"] = ps("idp", g.get("domainName"))
            for r in g.get("roles", []) or []:
                _role(ps, r)
    ip = a.get("ipAllowlist")
    if isinstance(ip, dict) and isinstance(ip.get("ipCidrs"), list):
        ip["ipCidrs"] = [ps("ip", c) for c in ip["ipCidrs"]]
    if isinstance(a.get("identityProviders"), list):
        for p in a["identityProviders"]:
            p["name"] = ps("idp", p.get("name"))

    # Quorum
    q = d.get("quorum", {})
    if isinstance(q.get("orgs"), dict):
        q["orgs"] = {ps("org", k): ps("org", v) for k, v in q["orgs"].items()}
    if isinstance(q.get("config"), dict):
        q["config"] = {ps("org", k): v for k, v in q["config"].items()}
    for p in q.get("policies", []) or []:
        p["policyId"] = ps("policy", p.get("policyId"))
        p["policyName"] = ps("policy", p.get("policyName"))
        p["orgId"] = ps("org", p.get("orgId"))
        p["orgName"] = ps("org", p.get("orgName"))

    # SLAs: names identify business units
    for s in d.get("sla", {}).get("slas", []) or []:
        s["id"] = ps("sla", s.get("id"))
        s["name"] = ps("sla", s.get("name"))

    # Offsite: SLA, archive location and replication cluster names. Scoring reads only the counts.
    # Use the same kinds as the SLA and cluster sections so one real name gets one pseudonym everywhere.
    for s in d.get("offsite", {}).get("slas", []) or []:
        s["name"] = ps("sla", s.get("name"))
        for t in s.get("archiveTargets", []) or []:
            t["name"] = ps("archive", t.get("name"))
            # Same pseudonym as the clusters section, so the report can still join a cluster to its archive.
            if "clusterId" in t:
                t["clusterId"] = ps("cluster", t.get("clusterId"))
        for t in s.get("replicationTargets", []) or []:
            t["cluster"] = ps("cluster", t.get("cluster"))

    # Recovery plans: names identify applications and business units.
    for p in d.get("recovery", {}).get("plans", []) or []:
        p["name"] = ps("plan", p.get("name"))

    # Clusters
    for c in d.get("clusters", {}).get("clusters", []) or []:
        c["id"] = ps("cluster", c.get("id"))
        c["name"] = ps("cluster", c.get("name"))

    # Inventory
    inv = d.get("inventory", {})
    un = inv.get("unprotected", {})
    for r in un.get("rows", []) or []:
        r["id"] = ps("obj", r.get("id"))
        r["name"] = ps("obj", r.get("name"))
        r["location"] = ps("loc", r.get("location"))
        r["clusterName"] = ps("cluster", r.get("clusterName"))
    for tally, kind in (("byCluster", "cluster"), ("byLocation", "loc")):
        for t in un.get(tally, []) or []:
            t["key"] = ps(kind, t["key"])
    env = inv.get("vmEnvironment", {})
    for t in env.get("matchedText", []) or []:
        t["key"] = ps("obj", t["key"])
    for v in env.get("unprotectedNonProd", []) or []:
        v["name"] = ps("obj", v.get("name"))
        v["cluster"] = ps("cluster", v.get("cluster"))
        v["signals"] = [[s[0], ps("obj", s[1])] for s in v.get("signals", [])]

    # Threat monitoring roots (cloud account / subscription names and ids)
    # CDM_CLUSTER items are clusters, so they share pseudonyms with the clusters section above.
    for root_type, root in (d.get("threat", {}).get("roots") or {}).items():
        if not isinstance(root, dict):
            continue
        kind = "cluster" if root_type == "CDM_CLUSTER" else "acct"
        for i in (root.get("items") or []) + (root.get("notAssessed") or []):
            i["id"] = ps(kind, i.get("id"))
            i["name"] = ps(kind, i.get("name"))

    # Alerting. Current bundles hold counts only. Bundles collected before 2026-10-16 also stored the raw webhook
    # records (names, ids, providers), which no rule reads, so drop them rather than pseudonymize them.
    wh = d.get("detection", {}).get("webhooks")
    if isinstance(wh, dict):
        wh.pop("items", None)

    # Error stubs can echo ids or hostnames from the API; keep the shape, drop the text.
    for name, status in list(b.get("status", {}).items()):
        if status != "ok":
            b["status"][name] = "error (detail withheld by redaction)"
    _strip_error_text(d)

    # Last line of defense: any email still present anywhere is pseudonymized.
    b = json.loads(_scrub_free_text(json.dumps(b), ps))
    b["redacted"] = True
    return b, {"salt_note": "keep this file; it reverses the pseudonyms", "map": ps.map}


def _strip_error_text(node):
    if isinstance(node, dict):
        if "error" in node:
            node["error"] = "withheld by redaction"
        for v in node.values():
            _strip_error_text(v)
    elif isinstance(node, list):
        for v in node:
            _strip_error_text(v)
