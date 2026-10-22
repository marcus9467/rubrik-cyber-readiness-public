"""Which Rubrik edition each detection capability belongs to.

  Foundation  no Data Threat Analytics
  Business    Anomaly Detection only
  Enterprise  everything: Anomaly Detection, Threat Monitoring, Threat Hunting and Sensitive Data Discovery

Edition is a label and never an input to a score. Every tenant is measured against the full standard, so a gap in
an Enterprise capability is a gap whatever edition the tenant holds, and the report says which edition closes it.
"""

FOUNDATION, BUSINESS, ENTERPRISE = "Foundation", "Business", "Enterprise"

# Lowest edition that includes the capability.
CAPABILITY_EDITION = {
    "Anomaly Detection": BUSINESS,
    "Threat Monitoring": ENTERPRISE,
    "Threat Hunting": ENTERPRISE,
    "Sensitive Data Discovery": ENTERPRISE,
}

# Rule id -> capability it closes the gap on.
RULE_CAPABILITY = {
    "V-1": "Anomaly Detection", "T-3": "Anomaly Detection",
    "V-2": "Threat Monitoring", "T-1": "Threat Monitoring", "T-10": "Threat Monitoring", "T-11": "Threat Monitoring",
    "V-4": "Sensitive Data Discovery", "T-2": "Sensitive Data Discovery",
}


def edition_of(rule_id):
    """{'edition': 'Business' | 'Enterprise' | None, 'capability': name | None}. None means any edition."""
    cap = RULE_CAPABILITY.get(rule_id)
    return {"edition": CAPABILITY_EDITION.get(cap), "capability": cap}


def bucket(tag, rule_id):
    """Report bucket: visibility | fix_now | process. Edition never moves a finding between buckets."""
    return tag if tag in ("fix_now", "process", "visibility") else "process"
