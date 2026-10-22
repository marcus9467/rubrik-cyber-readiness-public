"""RSC's own Data Health / Resilience Cockpit scores, used to cross-check our counts."""

DHRC_Q = """
query Dhrc {
  allDhrcScores(timespan: WEEK) {
    category value calculatedAt date earliestMetric
    context { metrics { metric value maxValue weight impact version } }
  }
}
"""


def collect(client):
    rows = client.query(DHRC_Q)["allDhrcScores"]
    latest = {}
    for r in rows:
        cur = latest.get(r["category"])
        if cur is None or (r["date"] or "") > (cur["date"] or ""):
            latest[r["category"]] = r
    return {
        "scores": {
            cat: {
                "value": round(r["value"], 1),
                "date": r["date"],
                "metrics": [
                    {k: m[k] for k in ("metric", "value", "maxValue", "weight", "impact")}
                    for m in (r["context"] or {}).get("metrics", [])
                ],
            }
            for cat, r in latest.items()
        },
        "history": [{"category": r["category"], "date": r["date"], "value": round(r["value"], 1)} for r in rows],
    }
