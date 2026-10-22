"""Offsite copies: which SLA Domains replicate to another cluster or archive to cloud.

A copy flag is True / False only when RSC returned the spec list; null means unknown and is never a gap.

Object counts are ACTIVE, PROTECTED objects per SLA, from one count-only query per SLA. RSC's own
protectedObjectCount also counts relic and archived records (on a lab tenant it was nearly double), which made
the offsite shares describe records no one is backing up. If a per-SLA count fails, that SLA falls back to the
record count and is listed in `fallbackSlas`, so the two are never mixed silently.
"""

COUNT_Q = "query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}"

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
          archivalLocationToClusterMapping { cluster { id } location { name targetType } }
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
                        "clusterId": (m.get("cluster") or {}).get("id"),
                        "immutable": bool(a.get("isComplianceImmutabilityEnabled"))})
    return out


def _repl_targets(specs):
    return [{"cluster": (r.get("cluster") or {}).get("name"),
             "type": (r.get("targetMapping") or {}).get("targetType")} for r in specs or []]


def _active_count(client, sla_id):
    f = {"slaDomain": {"id": [sla_id]}, "objectState": ["ACTIVE"], "protectionStatus": ["Protected"]}
    return client.query(COUNT_Q, {"f": f})["snappableConnection"]["count"]


def collect(client):
    slas = client.paginate(OFFSITE_Q, "slaDomains")
    # Pseudo-SLAs (unprotected, do not protect) carry no protectedObjectCount field.
    real = [s for s in slas if "protectedObjectCount" in s and not s.get("isArchived")]
    per_sla, fallback = [], []
    for s in real:
        records = s.get("protectedObjectCount")
        if not records:
            continue
        try:
            n = _active_count(client, s["id"])
        except Exception:
            n = records  # unknown, not zero: keep the record count and say so
            fallback.append(s["name"])
        if not n:
            continue  # only relic or archived records sit under this SLA
        per_sla.append({
            "name": s["name"], "objects": n, "recordCount": records,
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
        "basis": "active-protected",
        "fallbackSlas": len(fallback),
        "recordCount": sum(p["recordCount"] for p in per_sla),
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
