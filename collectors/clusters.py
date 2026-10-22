"""CDM cluster posture: version, health, encryption, air gap, quorum, support tunnel, end of support."""

CLUSTERS_Q = """
query Clusters($after: String) {
  clusterConnection(after: $after, first: 200) {
    count
    nodes {
      id name version type productType status isHealthy
      encryptionEnabled isAirGapped isTprEnabled isClusterRemovalTprEnabled
      isTunnelEnabled eosStatus eosDate estimatedRunway cyberEventLockdownMode
      lastConnectionTime
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def collect(client):
    nodes = client.paginate(CLUSTERS_Q, "clusterConnection")
    flag = lambda key, val: sum(c.get(key) is val for c in nodes)
    return {
        "total": len(nodes),
        "connected": sum(c["status"] == "Connected" for c in nodes),
        "unhealthy": flag("isHealthy", False),
        "encryptionOff": flag("encryptionEnabled", False),
        "airGapped": flag("isAirGapped", True),
        # None means RSC did not report it (unknown), which is not the same as off.
        "tprOff": flag("isTprEnabled", False),
        "tprUnknown": sum(c.get("isTprEnabled") is None for c in nodes),
        "clusterRemovalTprOff": flag("isClusterRemovalTprEnabled", False),
        "clusterRemovalTprUnknown": sum(c.get("isClusterRemovalTprEnabled") is None for c in nodes),
        "supportTunnelOpen": flag("isTunnelEnabled", True),
        "versions": sorted({c["version"] for c in nodes if c.get("version")}),
        "clusters": nodes,
    }
