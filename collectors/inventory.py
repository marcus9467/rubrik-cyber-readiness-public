"""Coverage: protected vs supported per platform, plus detail on unprotected active objects."""
import re
from collections import Counter

COVERAGE_Q = """
query Coverage($days: Int!) {
  dataProtectionCoverageSummary(historicalDeltaDays: $days) {
    overallProtectionCoverage {
      platformCategory protectedObjectsCount supportedObjectsCount
      protectionPercentCoverage violatedSensitiveObjects
    }
    platformCoverage {
      platformCategory protectedObjectsCount supportedObjectsCount
      protectionPercentCoverage violatedSensitiveObjects
    }
  }
}
"""


UNPROTECTED_Q = """
query Unprotected($after: String) {
  snappableConnection(
    after: $after
    first: 500
    filter: {protectionStatus: [NoSla, DoNotProtect], objectState: [ACTIVE]}
  ) {
    count
    nodes {
      id name objectType location protectionStatus complianceStatus
      logicalBytes cluster { id name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Name/location tokens that suggest non-production. Heuristic only; the report labels it as such.
NONPROD_RE = re.compile(r"(?<![a-z])(dev|test|tst|qa|uat|stg|stage|staging|sandbox|lab|poc|demo)(?![a-z])", re.I)


VM_Q = """
query Vms($after: String) {
  vSphereVmNewConnection(after: $after, first: 500) {
    count
    nodes {
      name isRelic templateType
      effectiveSlaDomain { id name }
      logicalPath { name objectType }
      vsphereTagPath { name objectType }
      allTags { key value }
      cluster { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Folder names that are structural, never evidence of environment.
STRUCTURAL_FOLDERS = {"vm", "templates", "datacenters", "datacenter"}
UNPROTECTED_SLA_IDS = {"UNPROTECTED", "DO_NOT_PROTECT"}


def _vm_signals(vm):
    """Return [(source, matched_text)] for every non-prod hint on one VM."""
    hits = []
    for p in vm["logicalPath"]:
        if p["objectType"] == "VSphereFolder" and p["name"].lower() not in STRUCTURAL_FOLDERS:
            if NONPROD_RE.search(p["name"]):
                hits.append(("folder", p["name"]))
    for p in vm["vsphereTagPath"]:
        if p["objectType"] in ("VSphereTag", "VSphereTagCategory") and NONPROD_RE.search(p["name"]):
            hits.append(("vsphereTag", p["name"]))
    for t in vm["allTags"]:
        if NONPROD_RE.search(f"{t['key']} {t['value']}"):
            hits.append(("rscTag", f"{t['key']}={t['value']}".strip("=")))
    if NONPROD_RE.search(vm["name"]):
        hits.append(("vmName", vm["name"]))
    return hits


def _vm_environment(client):
    entries = [v for v in client.paginate(VM_Q, "vSphereVmNewConnection") if not v["isRelic"]]
    templates = [v for v in entries if v["templateType"] != "VM"]
    entries = [v for v in entries if v["templateType"] == "VM"]

    # The same VM appears once per cluster that sees its vCenter, each with its own SLA.
    # Collapse to one record per (vCenter, folder path, name); protected if ANY cluster protects it.
    groups = {}
    for v in entries:
        vcenter = next((p["name"] for p in v["logicalPath"] if p["objectType"] == "VSphereVCenter"), "?")
        folders = tuple(p["name"] for p in v["logicalPath"] if p["objectType"] == "VSphereFolder")
        groups.setdefault((vcenter, folders, v["name"]), []).append(v)
    vms = []
    for (vcenter, folders, name), grp in groups.items():
        first = grp[0]
        prot = [g for g in grp if g["effectiveSlaDomain"]["id"] not in UNPROTECTED_SLA_IDS]
        first["protected"] = bool(prot)
        first["clusterEntries"] = len(grp)
        first["clustersProtecting"] = len(prot)
        first["signals"] = _vm_signals(first)
        vms.append(first)
    sla_ids = Counter(v["effectiveSlaDomain"]["id"] for v in entries)
    nonprod = [v for v in vms if v["signals"]]
    prodlike = [v for v in vms if not v["signals"]]
    folder_only = [v for v in nonprod if any(s[0] in ("folder", "vsphereTag", "rscTag") for s in v["signals"])]
    return {
        "activeVmEntries": len(entries),
        "templatesExcluded": len(templates),
        "activeVms": len(vms),
        "partiallyProtected": sum(0 < v["clustersProtecting"] < v["clusterEntries"] for v in vms),
        "slaIdCounts": [{"key": k, "count": n} for k, n in sla_ids.most_common(8)],
        "slaIdNote": "00000000-0000-0000-0000-000000000002 is the built-in Bronze SLA (protected).",
        "nonProd": {
            "total": len(nonprod),
            "protected": sum(v["protected"] for v in nonprod),
            "unprotected": sum(not v["protected"] for v in nonprod),
            "structuralSignalTotal": len(folder_only),
        },
        "prodLike": {
            "total": len(prodlike),
            "protected": sum(v["protected"] for v in prodlike),
            "unprotected": sum(not v["protected"] for v in prodlike),
        },
        "signalSources": _tally([s for v in nonprod for s in {x[0] for x in v["signals"]}], lambda x: x),
        "matchedText": _tally([s[1] for v in nonprod for s in v["signals"]], lambda x: x)[:30],
        "unprotectedNonProd": [
            {"name": v["name"], "cluster": v["cluster"]["name"], "signals": v["signals"]}
            for v in nonprod if not v["protected"]
        ],
    }


def _reconciliation(client, summary):
    q = "query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}"
    n = lambda f: client.query(q, {"f": f})["snappableConnection"]["count"]
    active = {"objectState": ["ACTIVE"]}
    return {
        "snappables": {
            "active": n(active),
            "relic": n({"objectState": ["RELIC"]}),
            "archived": n({"objectState": ["ARCHIVED"]}),
            "activeProtected": n({**active, "protectionStatus": ["Protected"]}),
            "activeNoSla": n({**active, "protectionStatus": ["NoSla"]}),
            "activeDoNotProtect": n({**active, "protectionStatus": ["DoNotProtect"]}),
        },
        "coverageSummary": {
            "supported": summary["overallProtectionCoverage"]["supportedObjectsCount"],
            "protected": summary["overallProtectionCoverage"]["protectedObjectsCount"],
        },
        "note": "Counts are object records, not distinct workloads. Do not dedupe by name: Azure DevOps "
                "repos repeat a name across projects (verified: same name, different project and URL, "
                "each a separate repository), and the row location shows only the organization. A few "
                "objects (VMs, databases, domain controllers) appear once per replicating cluster under "
                "the same id, so the unprotected list is deduped by id and VM statements use "
                "vmEnvironment. The RSC cockpit PROTECTED_OBJECTS metric (see dhrc) is close to "
                "active plus protected-relic objects but is computed daily and does not match exactly. "
                "dataProtectionCoverageSummary uses a different, smaller object universe that we could "
                "not reproduce from snappable data. Reports quote object records and cite the cockpit "
                "figure alongside.",
    }


BACKUP_HEALTH_RANGE = "PAST_7_DAYS"


def _backup_health(client):
    """Active, protected objects by SLA compliance over the past 7 days.

    The default window is the whole protection lifetime, which flags an object forever for one old miss, so the
    window is explicit. NOT_AVAILABLE and EMPTY mean RSC could not say, and are kept apart from a pass or a fail.
    """
    q = "query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}"
    base = {"objectState": ["ACTIVE"], "protectionStatus": ["Protected"], "slaTimeRange": BACKUP_HEALTH_RANGE}
    n = lambda status: client.query(q, {"f": {**base, "complianceStatus": [status]}})["snappableConnection"]["count"]
    return {
        "window": BACKUP_HEALTH_RANGE,
        "inCompliance": n("IN_COMPLIANCE"),
        "outOfCompliance": n("OUT_OF_COMPLIANCE"),
        "notAvailable": n("NOT_AVAILABLE"),
        "empty": n("EMPTY"),
    }


def _dedupe_by_id(rows):
    """Keep the first row per object id. The same object is listed once per replicating cluster."""
    seen, out = set(), []
    for r in rows:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        out.append(r)
    return out


def _tally(rows, key):
    c = Counter(key(r) for r in rows)
    return [{"key": k, "count": n} for k, n in c.most_common()]


def collect(client):
    s = client.query(COVERAGE_Q, {"days": 30})["dataProtectionCoverageSummary"]
    for p in s["platformCoverage"] + [s["overallProtectionCoverage"] or {}]:
        if p:
            p["unprotectedObjectsCount"] = p["supportedObjectsCount"] - p["protectedObjectsCount"]

    rows = _dedupe_by_id(client.paginate(UNPROTECTED_Q, "snappableConnection"))
    for r in rows:
        r["clusterName"] = (r.pop("cluster") or {}).get("name") or "unknown"
        r["likelyNonProd"] = bool(NONPROD_RE.search(f"{r['name']} {r['location']}"))
    nonprod = [r for r in rows if r["likelyNonProd"]]
    s["unprotected"] = {
        "total": len(rows),
        "noSla": sum(r["protectionStatus"] == "NoSla" for r in rows),
        "doNotProtect": sum(r["protectionStatus"] == "DoNotProtect" for r in rows),
        "likelyNonProd": len(nonprod),
        "logicalBytes": sum(r["logicalBytes"] or 0 for r in rows),
        "byType": _tally(rows, lambda r: r["objectType"]),
        "byCluster": _tally(rows, lambda r: r["clusterName"]),
        "byLocation": _tally(rows, lambda r: r["location"].split("/")[0] or "unknown")[:25],
        "nonProdByType": _tally(nonprod, lambda r: r["objectType"]),
        "rows": rows,
    }
    s["vmEnvironment"] = _vm_environment(client)
    s["backupHealth"] = _backup_health(client)
    s["reconciliation"] = _reconciliation(client, s)
    return s
