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


def collect(client):
    out = {"roots": {}}
    for root_type in ROOT_TYPES:
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
    return out
