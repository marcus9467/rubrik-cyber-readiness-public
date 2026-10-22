"""Per-cluster inventory: version, status, end-of-support, and which clusters archive to Rubrik Cloud Vault.

Built from data the collectors already hold. Nothing here queries RSC.

RCV is recognised by archival location targetType, never by name: names are pseudonymized in a redacted bundle.
RSC reports RCV on Azure as RCS_AZURE, so that value counts as RCV.

An SLA's archive mapping is per cluster, but the object count is per SLA. A cluster's `objectsUnderRcvSlas` is
therefore the active protected objects under SLAs that archive from that cluster to RCV. It is an upper bound on
what that cluster sends, because an SLA can span several clusters. The report says so.
"""

RCV_TYPES = {"RCS_AZURE", "RCV_AWS", "RCV_GCP"}
# RSC reports these when it has no end-of-support information. They are unknown, not supported.
EOS_UNKNOWN = {None, "", "EOS_STATUS_UNKNOWN", "unknown", "UNKNOWN"}
# The four values of RSC's ClusterEosStatus enum. UNKNOWN is handled above and never reaches this table.
EOS_LABEL = {
    "EOS_STATUS_SUPPORTED": "Supported",
    "EOS_STATUS_PLAN_UPGRADE": "Plan upgrade",
    "EOS_STATUS_UNSUPPORTED": "Out of support",
}
# Older fixtures and mocks used these. Kept so a bundle built from them still reads sensibly.
EOS_LABEL.update({"SOON": "Plan upgrade", "OK": "Supported"})


def _eos(c):
    status = c.get("eosStatus")
    if status in EOS_UNKNOWN:
        return {"label": "Not reported", "date": None, "known": False}
    date = c.get("eosDate")
    return {"label": EOS_LABEL.get(status, str(status).replace("EOS_STATUS_", "").replace("_", " ").title()),
            "date": None if date in EOS_UNKNOWN else date, "known": True}


def _base_version(v):
    """9.6.1-p1-33607 -> 9.6.1, for grouping. The full string is still what the table shows."""
    return str(v).split("-")[0] if v else None


def cluster_rows(data):
    """One row per CDM-type cluster, or [] if the clusters section is missing or an error stub."""
    sec = data.get("clusters")
    if not isinstance(sec, dict) or "error" in sec or not isinstance(sec.get("clusters"), list):
        return []
    rcv = _rcv_by_cluster(data.get("offsite"))
    rows = []
    for c in sec["clusters"]:
        eos = _eos(c)
        r = rcv.get(c.get("id"), {"slas": 0, "objects": 0})
        rows.append({
            "id": c.get("id"), "name": c.get("name"), "type": c.get("type"), "product": c.get("productType"),
            "version": c.get("version"), "baseVersion": _base_version(c.get("version")),
            "connected": c.get("status") == "Connected", "status": c.get("status"),
            "healthy": c.get("isHealthy"), "eos": eos, "runwayDays": c.get("estimatedRunway"),
            "rcvSlas": r["slas"], "objectsUnderRcvSlas": r["objects"], "toRcv": r["slas"] > 0,
        })
    return rows


def _rcv_by_cluster(offsite):
    """{cluster id: {slas, objects}} for SLAs whose archive target is RCV. Empty if the data is not there."""
    if not isinstance(offsite, dict) or "error" in offsite:
        return {}
    out = {}
    for s in offsite.get("slas") or []:
        seen = set()
        for t in s.get("archiveTargets") or []:
            cid = t.get("clusterId")
            if t.get("type") in RCV_TYPES and cid and cid not in seen:
                seen.add(cid)
                e = out.setdefault(cid, {"slas": 0, "objects": 0})
                e["slas"] += 1
                e["objects"] += s.get("objects") or 0
    return out


def rcv_known(data):
    """True only if archive targets carry a cluster id. Older bundles do not, so RCV by cluster is unknown."""
    off = data.get("offsite")
    if not isinstance(off, dict) or "error" in off:
        return False
    targets = [t for s in off.get("slas") or [] for t in s.get("archiveTargets") or []]
    return not targets or all("clusterId" in t for t in targets)


def summary(data):
    """Counts for the scorecard line, or None when there is nothing to summarise."""
    rows = cluster_rows(data)
    if not rows:
        return None
    known = rcv_known(data)
    versions = {}
    for r in rows:
        versions[r["baseVersion"] or "unknown"] = versions.get(r["baseVersion"] or "unknown", 0) + 1
    return {
        "clusters": len(rows), "connected": sum(r["connected"] for r in rows),
        "versions": versions, "rcvKnown": known,
        "toRcv": sum(r["toRcv"] for r in rows) if known else None,
        "notToRcv": sum(not r["toRcv"] for r in rows) if known else None,
        "eosUnknown": sum(not r["eos"]["known"] for r in rows),
    }
