"""Wording shared by the PDF renderers, so the reportlab and HTML reports never drift apart."""

# Report buckets (editions.bucket). "enterprise" only appears for a confirmed entitlement.
BUCKET_LABEL = {
    "visibility": "Visibility gap",
    "fix_now": "Fix now",
    "process": "Process",
    "enterprise": "Enterprise Edition",
    "unconfirmed": "Edition unconfirmed",
}
BUCKET_NOTE = {
    "visibility": "A detection capability the tenant cannot see. Without it the team is blind to this class of attack.",
    "fix_now": "Setup or configuration your team can start now.",
    "process": "Needs a runbook, owner or decision.",
    "enterprise": "Capability requires Enterprise Edition (entitlement confirmed).",
    "unconfirmed": "Edition not confirmed. Do not present as an upgrade benefit until checked.",
}

PHASE_TITLE = {
    30: "First 30 days: configuration changes",
    60: "Days 31 to 60: remaining configuration and urgent process work",
    90: "Days 61 to 90: process and runbook work",
    "decide": "Decide after licensing is settled",
}

METHOD_NOTES = [
    "Data was collected read-only through the RSC GraphQL API using a service account.",
    "Scores start at 100 per area and lose 25, 15, 7 or 3 points per critical, high, medium or low "
    "finding. This is a simple heuristic to show relative gaps, not an industry benchmark.",
    "Several thresholds (90 days stale, 24 hour MFA remember window, 2 or fewer account owners, "
    "2 or more quorum approvers, 12 character passwords) are guidance values, not Rubrik limits.",
    "Object counts are RSC object records, not distinct workloads. A VM can appear once per cluster; "
    "VM figures are collapsed to one record per VM, and templates are excluded.",
    "Anomaly detection, threat monitoring, threat hunting and sensitive data discovery are scored by what RSC "
    "can show for the tenant. A capability with no data scores 0. The data cannot tell unavailable from "
    "switched off from hidden from the assessing account, so the report does not say which.",
    "Test/dev detection matches names such as dev, test, qa, uat and staging. It is a heuristic and "
    "should be confirmed with the customer.",
    "RSC's own resilience scores are shown for comparison. Their object counts differ from the "
    "per-object counts here and the difference has not been reconciled.",
    "The NIST CSF and HIPAA mapping is the author's judgment. It has not been reviewed by compliance "
    "and is not a statement of compliance.",
]
