"""Offsite copies: which SLA Domains replicate to another cluster or archive to cloud.

Uses the object count RSC keeps on each SLA, so no per-object queries. A copy flag is
True / False only when RSC returned the spec list; null means unknown and is never a gap.
"""

OFFSITE_Q = """
query Offsite($after: String) {
  slaDomains(after: $after, first: 200, shouldShowProtectedObjectCount: true) {
    count
    nodes {
      id name
      ... on GlobalSlaReply {
        protectedObjectCount isArchived
        baseFrequency { duration unit }
        archivalSpecs {
          isComplianceImmutabilityEnabled
          archivalLocationToClusterMapping { location { name targetType } }
        }
        replicationSpecsV2 { cluster { name } targetMapping { targetType } }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def _flag(specs):
    """True/False when the list was returned, None when it was not (unknown)."""
    return None if specs is None else bool(specs)


def _archive_targets(specs):
    out = []
    for a in specs or []:
        for m in a.get("archivalLocationToClusterMapping") or []:
            loc = m.get("location") or {}
            out.append({"name": loc.get("name"), "type": loc.get("targetType"),
                        "immutable": bool(a.get("isComplianceImmutabilityEnabled"))})
    return out


def _repl_targets(specs):
    return [{"cluster": (r.get("cluster") or {}).get("name"),
             "type": (r.get("targetMapping") or {}).get("targetType")} for r in specs or []]


def collect(client):
    slas = client.paginate(OFFSITE_Q, "slaDomains")
    # Pseudo-SLAs (unprotected, do not protect) carry no protectedObjectCount field.
    real = [s for s in slas if "protectedObjectCount" in s and not s.get("isArchived")]
    per_sla = []
    for s in real:
        n = s.get("protectedObjectCount")
        if not n:
            continue
        per_sla.append({
            "name": s["name"], "objects": n,
            "replication": _flag(s.get("replicationSpecsV2")),
            "archival": _flag(s.get("archivalSpecs")),
            "replicationTargets": _repl_targets(s.get("replicationSpecsV2")),
            "archiveTargets": _archive_targets(s.get("archivalSpecs")),
            "frequency": s.get("baseFrequency"),
        })

    def objs(pred):
        return sum(p["objects"] for p in per_sla if pred(p))

    known_r = objs(lambda p: p["replication"] is not None)
    known_a = objs(lambda p: p["archival"] is not None)
    known_both = objs(lambda p: p["replication"] is not None and p["archival"] is not None)
    return {
        "slasInUse": len(per_sla),
        "objects": objs(lambda p: True),
        "objectsReplicationKnown": known_r,
        "objectsArchivalKnown": known_a,
        "objectsBothKnown": known_both,
        "noReplication": objs(lambda p: p["replication"] is False),
        "noArchival": objs(lambda p: p["archival"] is False),
        "singleCopy": objs(lambda p: p["replication"] is False and p["archival"] is False),
        "withReplication": objs(lambda p: p["replication"] is True),
        "withArchival": objs(lambda p: p["archival"] is True),
        "slas": per_sla,
    }
