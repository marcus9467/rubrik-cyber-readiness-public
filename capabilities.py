"""What the tenant can actually see: four detection capabilities, each scored 0 to 100.

  Anomaly Detection         unusual change in backup data, such as mass encryption or deletion
  Threat Monitoring         continuous scan of backups for known malicious indicators
  Threat Hunting            on-demand search of backups for an indicator during an incident
  Sensitive Data Discovery  where regulated data lives and who can open it

A capability Rubrik cannot show data for scores 0. It is never "not assessed", because for a customer the
absence of this view is the finding. A 0 can mean the capability is unavailable, switched off, or not
readable by the account that ran the assessment; the data cannot tell those apart, so the wording stays
neutral about the cause.

States:
  active         covered everywhere RSC reports on (100)
  partial        covered on some of it (1 to 99)
  off            RSC reports on it and nothing is turned on (0)
  blind          RSC returned an error or no data for it (0)
  not_collected  the collector never ran, which means an older bundle. Not scored, not compared.

Thresholds are the author's guidance, not Rubrik limits: threat hunting counts as in use if a hunt ran in the
last 90 days (100), as lapsed if hunts exist but none in 90 days (50), and as unused otherwise (0).
"""

DOMAINS = ("Anomaly Detection", "Threat Monitoring", "Threat Hunting", "Sensitive Data Discovery")
RULE_IDS = {"Anomaly Detection": "V-1", "Threat Monitoring": "V-2", "Threat Hunting": "V-3",
            "Sensitive Data Discovery": "V-4"}
# Findings whose resolution lifts the ceiling on a domain's score (see ceilings()).
FIXERS = {"Anomaly Detection": ("V-1",), "Threat Monitoring": ("V-2", "T-1"), "Threat Hunting": ("V-3",),
          "Sensitive Data Discovery": ("V-4",)}
STATE_LABEL = {"active": "Active", "partial": "Partial coverage", "off": "Not turned on",
               "blind": "No data returned", "not_collected": "Not collected"}
HUNT_WINDOW_DAYS = 90  # GUIDANCE

# Wording for the "prepared for" cards and the V findings. Plain language, no edition claims.
PREPARED_FOR = {
    "Anomaly Detection": "ransomware encrypting or mass-deleting your backup data",
    "Threat Monitoring": "malware that is already sitting in your backups",
    "Threat Hunting": "an active incident where you must search every backup for the attacker's trail",
    "Sensitive Data Discovery": "a breach where you must say exactly what data was exposed",
}
CONSEQUENCE = {
    "Anomaly Detection": "Nothing tells your team that backup data is changing abnormally, so an attack can run "
                         "until someone notices something else is wrong.",
    "Threat Monitoring": "Backups are not scanned for known malicious indicators, so a restore point can carry "
                         "the attacker straight back in.",
    "Threat Hunting": "In an incident your team cannot search backups for an indicator, so scoping the attack "
                      "and choosing a clean restore point is guesswork.",
    "Sensitive Data Discovery": "Nobody can say where regulated data lives or who can open it, so after a breach "
                                "the exposure cannot be sized.",
}
GAP_TITLE = {
    "Anomaly Detection": ("No visibility into ransomware activity in backup data",
                          "Ransomware detection covers only part of the estate"),
    "Threat Monitoring": ("No visibility into malware inside backups",
                          "Malware scanning covers only part of the estate"),
    "Threat Hunting": ("No ability to hunt for threats in backups",
                       "Threat hunting has lapsed"),
    "Sensitive Data Discovery": ("No visibility into where sensitive data lives",
                                 "Sensitive data discovery covers only part of the estate"),
}
BLIND_NOTE = ("RSC returned no data for this. It is unavailable, switched off, or hidden from the account that "
              "ran the assessment; the customer's administrator can confirm which.")


def _is_stub(x):
    return isinstance(x, dict) and "error" in x


def _section(data, status, status_key):
    """'ok' | 'error' | 'missing'. missing means the collector never ran (older bundle)."""
    st = (status or {}).get(status_key)
    if st is not None and st != "ok":
        return "error"
    return "ok" if status_key in data else "missing"


def _result(domain, state, share, evidence):
    score = {"active": 100, "off": 0, "blind": 0, "not_collected": None}.get(state)
    if state == "partial":
        score = max(1, min(99, round((share or 0) * 100)))
    return {"domain": domain, "rule": RULE_IDS[domain], "state": state, "score": score, "share": share,
            "evidence": evidence}


def _classify(share):
    return "active" if share >= 1 else "off" if share <= 0 else "partial"


def _metric(data, score_key, metric):
    s = (((data.get("dhrc") or {}).get("scores") or {}).get(score_key)) or {}
    return next((m for m in s.get("metrics") or [] if m.get("metric") == metric), None)


def _cluster_capability(domain, data, status, score_key, metric, what):
    st = _section(data, status, "dhrc")
    if st == "missing":
        return _result(domain, "not_collected", None, "")
    if st == "error" or _is_stub(data.get("dhrc")):
        return _result(domain, "blind", None, f"RSC returned no {what} data.")
    m = _metric(data, score_key, metric)
    if not m:
        return _result(domain, "blind", None, f"RSC reports no {what} data for this tenant.")
    if not m.get("maxValue"):
        # The metric counts clusters. A tenant with none (cloud or SaaS only) has nothing to measure here, which is
        # not the same as being blind, so it stays unscored rather than showing a false zero.
        return _result(domain, "not_collected", None, "")
    v, mx = m["value"] or 0, m["maxValue"]
    share = min(1.0, v / mx)
    state = _classify(share)
    return _result(domain, state, share, f"{what.capitalize()} is on for {v:g} of {mx:g} clusters.")


def anomaly(data, status):
    return _cluster_capability("Anomaly Detection", data, status, "ANOMALIES_DETECTED",
                               "RADAR_ENABLED_CLUSTERS", "anomaly detection")


def sensitive(data, status):
    return _cluster_capability("Sensitive Data Discovery", data, status, "SENSITIVE_DATA",
                               "DATA_DISCOVERY_ENABLED_CLUSTERS", "sensitive data discovery")


def monitoring(data, status):
    dom = "Threat Monitoring"
    st = _section(data, status, "threat")
    if st == "missing":
        return _result(dom, "not_collected", None, "")
    threat = data.get("threat")
    if st == "error" or not isinstance(threat, dict) or _is_stub(threat):
        return _result(dom, "blind", None, "RSC returned no threat monitoring data.")
    shares, parts = [], []
    # Same roots as rule T-1: Rubrik clusters plus cloud and SaaS accounts. Clusters RSC could not read are not in
    # the total (see notAssessed), so a disconnected cluster is neither credited nor counted as off.
    roots = [r for r in (threat.get("roots") or {}).values()
             if isinstance(r, dict) and not _is_stub(r) and r.get("total")]
    if roots:
        en, tot = sum(r["threatMonitoringEnabled"] for r in roots), sum(r["total"] for r in roots)
        shares.append(min(1.0, en / tot))
        parts.append(f"{en} of {tot} clusters, cloud accounts and SaaS accounts")
    objs = threat.get("objects")
    if isinstance(objs, dict) and not _is_stub(objs) and objs.get("supportedObjects"):
        en, sup = objs["enabledObjects"], objs["supportedObjects"]
        shares.append(min(1.0, en / sup))
        parts.append(f"{en:,} of {sup:,} workload objects"
                     + (" (RSC reports more enabled than supported, so this is counted as complete)"
                        if en > sup else ""))
    if not shares:
        return _result(dom, "blind", None, "Threat monitoring is not reporting on any account or object.")
    share = sum(shares) / len(shares)
    return _result(dom, _classify(share), share, "Threat monitoring is on for " + "; ".join(parts) + ".")


def hunting(data, status):
    dom = "Threat Hunting"
    st = _section(data, status, "detection")
    if st == "missing":
        return _result(dom, "not_collected", None, "")
    det = data.get("detection")
    if st == "error" or not isinstance(det, dict):
        return _result(dom, "blind", None, "RSC returned no threat hunting data.")
    h = det.get("hunts")
    if h is None:
        return _result(dom, "not_collected", None, "")  # collector predates hunt history
    if _is_stub(h):
        return _result(dom, "blind", None, "RSC returned no threat hunt history.")
    total, recent, latest = h.get("total") or 0, h.get("last90") or 0, (h.get("latest") or "")[:10]
    if recent > 0:
        return _result(dom, "active", 1.0, f"{recent} threat hunts ran in the last {HUNT_WINDOW_DAYS} days; "
                       f"the most recent was on {latest}.")
    if total > 0:
        return _result(dom, "partial", 0.5, f"{total} threat hunts have run, none in the last "
                       f"{HUNT_WINDOW_DAYS} days; the most recent was on {latest}.")
    return _result(dom, "off", 0.0, "No threat hunt has ever been run.")


_FUNCS = {"Anomaly Detection": anomaly, "Threat Monitoring": monitoring, "Threat Hunting": hunting,
          "Sensitive Data Discovery": sensitive}


def compute(data, status=None):
    """{domain: result} for the four capabilities, in display order."""
    status = status if status is not None else data.get("_status") or {}
    return {d: _FUNCS[d](data, status) for d in DOMAINS}


def ceilings(caps):
    """{domain: (score, fixer ids)} for capabilities scoring under 100. Used by the roadmap projection."""
    return {d: (c["score"], FIXERS[d]) for d, c in caps.items() if c["score"] is not None and c["score"] < 100}
