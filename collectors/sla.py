"""SLA domains: retention lock, replication, archival, and how many objects each protects."""
from collections import Counter

SLA_Q = """
query Slas($after: String) {
  slaDomains(after: $after, first: 200, shouldShowProtectedObjectCount: true) {
    count
    nodes {
      id name
      ... on GlobalSlaReply {
        isRetentionLockedSla retentionLockMode protectedObjectCount objectTypes
        isDefault isArchived
        archivalSpecs { isComplianceImmutabilityEnabled threshold thresholdUnit }
        replicationSpecsV2 { retentionDuration { duration unit } }
        baseFrequency { duration unit }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def collect(client):
    slas = client.paginate(SLA_Q, "slaDomains")
    # Skip the pseudo-SLAs RSC returns for unprotected / do-not-protect, they have no config.
    real = [s for s in slas if "isRetentionLockedSla" in s and not s.get("isArchived")]
    locked = [s for s in real if s["isRetentionLockedSla"]]
    in_use = [s for s in real if s["protectedObjectCount"] > 0]
    return {
        "total": len(real),
        "retentionLocked": len(locked),
        "inUse": len(in_use),
        "inUseLocked": sum(s["isRetentionLockedSla"] for s in in_use),
        "objectsOnLockedSlas": sum(s["protectedObjectCount"] for s in locked),
        "objectsOnAnySla": sum(s["protectedObjectCount"] for s in real),
        "withArchival": sum(bool(s["archivalSpecs"]) for s in real),
        "withImmutableArchival": sum(
            any(a["isComplianceImmutabilityEnabled"] for a in s["archivalSpecs"]) for s in real
        ),
        "withReplication": sum(bool(s["replicationSpecsV2"]) for s in real),
        "lockModes": [{"key": k, "count": n} for k, n in Counter(s["retentionLockMode"] for s in real).most_common()],
        "slas": real,
    }
