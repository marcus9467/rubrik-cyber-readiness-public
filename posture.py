"""Which domains a bundle actually assessed, and the overall score over them.

Shared by the report and by delta.py so both agree on what "assessed" means.
"""

from capabilities import DOMAINS as CAPABILITY_DOMAINS

# Domain -> collectors that must have succeeded for its score to mean anything.
# The three detection capabilities are not here: they are scored from what the tenant can see, so a collector
# failure is a 0 for them and never "not assessed" (see capabilities.py).
DOMAIN_SOURCES = {
    "Identity": ["identity"], "MFA": ["mfa"], "Quorum": ["quorum"], "Access": ["access"],
    "RBAC": ["identity", "access"],
    "Immutability": ["sla"], "Coverage": ["inventory"], "Platform": ["clusters"],
    "Alerting": ["detection"], "Recovery": ["recovery", "offsite"],
}
# Display order: the four capabilities sit together, ahead of Alerting and Recovery.
DOMAIN_ORDER = ["Identity", "MFA", "Quorum", "Access", "RBAC", "Immutability", "Coverage", "Platform",
                *CAPABILITY_DOMAINS, "Alerting", "Recovery"]


def has_error(node, depth=0):
    """True if a collected section, or a sub-section one or two levels down, is an error stub."""
    if isinstance(node, dict):
        if "error" in node:
            return True
        return depth < 2 and any(has_error(v, depth + 1) for v in node.values())
    return False


def domain_rows(result, data):
    """[(domain, score or None)]. None means not assessed: a collector failed or never ran.

    The three detection capabilities are the exception: they score 0 when RSC returns nothing."""
    status = result["collector_status"]
    caps = result.get("capabilities") or {}
    rows = []
    for dom in DOMAIN_ORDER:
        if dom in CAPABILITY_DOMAINS:
            # None only when the collector never ran (an older bundle), so it cannot be compared or scored.
            has = caps.get(dom, {}).get("score") is not None
            rows.append((dom, result["domain_scores"].get(dom) if has else None))
            continue
        sources = DOMAIN_SOURCES[dom]
        # A collector can report "ok" while individual sub-queries failed; treat those as not assessed.
        if dom == "Alerting":
            det = data.get("detection") or {}
            readable = status.get("detection") == "ok" and not has_error({k: det.get(k) for k in ("settings", "webhooks")})
        else:
            readable = all(status.get(s) == "ok" and not has_error(data.get(s)) for s in sources)
        if readable:
            rows.append((dom, result["domain_scores"].get(dom, 100)))
        else:
            rows.append((dom, None))
    return rows


def overall(rows):
    vals = [s for _, s in rows if s is not None]
    return round(sum(vals) / len(vals)) if vals else None
