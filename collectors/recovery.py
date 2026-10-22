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


def collect(client):
    nodes = client.paginate(PLANS_Q, "recoveryPlansBasicInfo")
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
