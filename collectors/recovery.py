"""Recovery readiness: do recovery plans exist, are they configured, and have they ever been run."""

PLANS_Q = """
query Plans($after: String) {
  recoveryPlansBasicInfo(after: $after, first: 100) {
    count
    nodes {
      id name isArchived recoveryPlanStatus recoveryPlanType workloadType numChildren
      latestRecovery { endTime recoveryOutcome isAdhocRecovery }
      recoverySchedule { nextRunTime }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


NOT_ENTITLED = "NOT_ENTITLED"


def collect(client):
    try:
        nodes = client.paginate(PLANS_Q, "recoveryPlansBasicInfo")
    except Exception as e:
        # RSC answers "Not entitled to access this resource" when the account's role lacks recovery plan access. That
        # is a permission gap on the assessment account, not a finding about the customer, so name it as such.
        if "not entitled" in str(e).lower():
            raise RuntimeError(f"{NOT_ENTITLED}: the assessment account's role cannot read recovery plans. "
                               f"{str(e)[:200]}") from e
        raise
    plans = [p for p in nodes if not p.get("isArchived")]
    ran = [p for p in plans if p.get("latestRecovery")]
    return {
        "total": len(plans),
        "configured": sum(p["recoveryPlanStatus"] == "CONFIGURED" for p in plans),
        "neverRun": sum(not p.get("latestRecovery") for p in plans),
        "lastRunFailed": sum(p["latestRecovery"]["recoveryOutcome"] == "FAILED" for p in ran),
        "scheduled": sum(bool((p.get("recoverySchedule") or {}).get("nextRunTime")) for p in plans),
        "cyberRecovery": sum(p["recoveryPlanType"] == "CYBER_RECOVERY" for p in plans),
        "plans": plans,
    }
