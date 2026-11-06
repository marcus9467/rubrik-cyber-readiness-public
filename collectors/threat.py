"""Threat Monitoring enablement for cloud-native and M365 roots, plus object-level enablement."""
from datetime import datetime, timedelta, timezone

ROOT_TYPES = [
    "CDM_CLUSTER", "AWS_NATIVE_ACCOUNT", "AZURE_NATIVE_SUBSCRIPTION",
    "GCP_NATIVE_PROJECT", "M365_SUBSCRIPTION", "CLOUD_DIRECT_CLUSTER",
]

# allEnablementItems requires a root object type; query each one separately.
ENABLEMENT_Q = """
query Enablement($type: ThreatHuntRootObjectType!) {
  threatAnalyticsEnablement {
    allEnablementItems(type: $type) {
      id name isHealthy threatMonitoringEnabled dataThreatAnalyticsEnabled isYaraProcessingEnabled
    }
  }
}
"""

OBJECT_STATS_Q = """
query Stats($begin: DateTime!) {
  threatMonitoringObjectEnablementStats(beginTime: $begin) { enabledObjects supportedObjects }
}
"""

# Objects Threat Monitoring has scanned. The three buckets sum to threatMonitoringObjectEnablementStats.enabledObjects on
# the lab tenant, so that figure is the whole object universe and not a count of objects with the feature on.
SCAN_Q = """
query ThreatScan($b: DateTime!) {
  threatMonitoringObjects(beginTime: $b) { objectsWithThreats objectsWithoutThreats unscannedObjects }
}
"""
SCAN_WINDOW_DAYS = 30  # fixed so reports from different runs compare


# allEnablementItems(type: CDM_CLUSTER) always returns [] (it is documented for cloud-native accounts). The
# per-cluster flag lives on Cluster.lambdaConfig. lambdaConfig is null for a cluster RSC cannot reach.
CDM_Q = """
query CdmThreat($after: String) {
  clusterConnection(after: $after, first: 200) {
    nodes {
      id name status isHealthy productType
      lambdaConfig {
        isThreatMonitoringEnabled isThreatMonitoringEnabledForActiveDirectory
        isSmartScanningEnabled enableThreatMonitoringFullScan orionYaraRemoteProcessingEnabled
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def cdm_root(nodes):
    """Shape per-cluster lambdaConfig like an allEnablementItems root. Clusters with no config are not assessed."""
    items, not_assessed = [], []
    for c in nodes:
        cfg = c.get("lambdaConfig")
        if not isinstance(cfg, dict):
            not_assessed.append({"id": c["id"], "name": c["name"], "status": c.get("status")})
            continue
        items.append({
            "id": c["id"], "name": c["name"], "isHealthy": bool(c.get("isHealthy")),
            "threatMonitoringEnabled": bool(cfg.get("isThreatMonitoringEnabled")),
            "dataThreatAnalyticsEnabled": False,
            "isYaraProcessingEnabled": bool(cfg.get("orionYaraRemoteProcessingEnabled")),
            "activeDirectoryEnabled": bool(cfg.get("isThreatMonitoringEnabledForActiveDirectory")),
            "smartScanningEnabled": bool(cfg.get("isSmartScanningEnabled")),
            "fullScanEnabled": bool(cfg.get("enableThreatMonitoringFullScan")),
        })
    return {
        "total": len(items),
        "threatMonitoringEnabled": sum(i["threatMonitoringEnabled"] for i in items),
        "dataThreatAnalyticsEnabled": 0,
        "unhealthy": sum(not i["isHealthy"] for i in items),
        "activeDirectoryEnabled": sum(i["activeDirectoryEnabled"] for i in items),
        "smartScanningEnabled": sum(i["smartScanningEnabled"] for i in items),
        "notAssessed": not_assessed,
        "items": items,
    }


def collect(client):
    out = {"roots": {}}
    for root_type in ROOT_TYPES:
        if root_type == "CDM_CLUSTER":
            try:
                nodes = [c for c in client.paginate(CDM_Q, "clusterConnection") if c.get("productType") == "CDM"]
                out["roots"][root_type] = cdm_root(nodes)
            except Exception as e:
                out["roots"][root_type] = {"error": str(e)[:300]}
            continue
        try:
            items = client.query(ENABLEMENT_Q, {"type": root_type})["threatAnalyticsEnablement"]["allEnablementItems"]
            out["roots"][root_type] = {
                "total": len(items),
                "threatMonitoringEnabled": sum(i["threatMonitoringEnabled"] for i in items),
                "dataThreatAnalyticsEnabled": sum(i["dataThreatAnalyticsEnabled"] for i in items),
                "unhealthy": sum(not i["isHealthy"] for i in items),
                "items": items,
            }
        except Exception as e:
            out["roots"][root_type] = {"error": str(e)[:300]}
    try:
        begin = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        out["objects"] = client.query(OBJECT_STATS_Q, {"begin": begin})["threatMonitoringObjectEnablementStats"]
    except Exception as e:
        out["objects"] = {"error": str(e)[:300]}
    try:
        begin = (datetime.now(timezone.utc) - timedelta(days=SCAN_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        s = client.query(SCAN_Q, {"b": begin})["threatMonitoringObjects"]
        out["scan"] = {"withThreats": s["objectsWithThreats"], "withoutThreats": s["objectsWithoutThreats"],
                       "unscanned": s["unscannedObjects"], "windowDays": SCAN_WINDOW_DAYS}
    except Exception as e:
        out["scan"] = {"error": str(e)[:300]}
    return out
