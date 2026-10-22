"""What the tenant can actually see: three detection capabilities, each scored 0 to 100.

  Anomaly Detection         unusual change in backup data, such as mass encryption or deletion
  Threat Monitoring         continuous scan of backups for known malicious indicators
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

Threat hunting is not scored. It is an on-demand action for an incident, so a tenant that has never run a hunt has
not failed anything. hunt_note() reports the history as one unscored line instead.
"""

DOMAINS = ("Anomaly Detection", "Threat Monitoring", "Sensitive Data Discovery")
RULE_IDS = {"Anomaly Detection": "V-1", "Threat Monitoring": "V-2", "Sensitive Data Discovery": "V-4"}
# Findings whose resolution lifts the ceiling on a domain's score (see ceilings()).
FIXERS = {"Anomaly Detection": ("V-1",), "Threat Monitoring": ("V-2", "T-1"), "Sensitive Data Discovery": ("V-4",)}
STATE_LABEL = {"active": "Active", "partial": "Partial coverage", "off": "Not turned on",
               "blind": "No data returned", "not_collected": "Not collected"}

# Wording for the "prepared for" cards and the V findings. Plain language, no edition claims.
PREPARED_FOR = {
    "Anomaly Detection": "ransomware encrypting or mass-deleting your backup data",
    "Threat Monitoring": "malware that is already sitting in your backups",
    "Sensitive Data Discovery": "a breach where you must say exactly what data was exposed",
}
CONSEQUENCE = {
    "Anomaly Detection": "Nothing tells your team that backup data is changing abnormally, so an attack can run "
                         "until someone notices something else is wrong.",
    "Threat Monitoring": "Backups are not scanned for known malicious indicators, so a restore point can carry "
                         "the attacker straight back in.",
    "Sensitive Data Discovery": "Nobody can say where regulated data lives or who can open it, so after a breach "
                                "the exposure cannot be sized.",
}
# Shown instead of CONSEQUENCE when the capability is on for part of the estate. The full line says the capability
# is absent, which contradicts the evidence printed above it.
PARTIAL_CONSEQUENCE = {
    "Anomaly Detection": "Backups outside the covered clusters are not watched for abnormal change, so an attack "
                         "there can run unnoticed.",
    "Threat Monitoring": "Backups outside the covered clusters and accounts are not scanned for known malicious "
                         "indicators, so a restore point from there can carry the attacker straight back in.",
    "Sensitive Data Discovery": "Regulated data outside the covered clusters is not classified, so after a breach "
                                "the exposure there cannot be sized.",
}


def consequence(domain, state):
    """The one-line business consequence. Partial coverage gets its own wording; off and blind get the full line."""
    return (PARTIAL_CONSEQUENCE if state == "partial" else CONSEQUENCE)[domain]


GAP_TITLE = {
    "Anomaly Detection": ("No visibility into ransomware activity in backup data",
                          "Ransomware detection covers only part of the estate"),
    "Threat Monitoring": ("No visibility into malware inside backups",
                          "Malware scanning covers only part of the estate"),
    "Sensitive Data Discovery": ("No visibility into where sensitive data lives",
                                 "Sensitive data discovery covers only part of the estate"),
}
BLIND_NOTE = "No data returned means RSC gave the assessment account nothing to read for that capability. It scores zero."


def _is_stub(x):
    return isinstance(x, dict) and "error" in x


def _section(data, status, status_key):
    """'ok' | 'error' | 'missing'. missing means the collector never ran (older bundle)."""
    st = (status or {}).get(status_key)
    if st is not None and st != "ok":
        return "error"
    return "ok" if status_key in data else "missing"


def _result(domain, state, share, evidence, reason=""):
    """reason: fixed text saying why a blind capability is blind. Never built from API text, so redaction cannot
    change it."""
    score = {"active": 100, "off": 0, "blind": 0, "not_collected": None}.get(state)
    if state == "partial":
        score = max(1, min(99, round((share or 0) * 100)))
    return {"domain": domain, "rule": RULE_IDS[domain], "state": state, "score": score, "share": share,
            "evidence": evidence, "reason": reason}


QUERY_FAILED = "The {} query failed, so RSC's answer is unknown."
NOT_REPORTED = "RSC does not report this capability for the tenant."
NOTHING_LISTED = "RSC lists no cluster, account or object for it."


def summary(caps):
    """Capabilities grouped by state, in display order, for the summary tile. not_collected ones are left out."""
    groups = {"active": [], "partial": [], "off": [], "blind": []}
    for dom in DOMAINS:
        c = caps.get(dom)
        if c is not None and c["state"] in groups:
            groups[c["state"]].append(dom)
    return groups


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
        return _result(domain, "blind", None, f"RSC returned no {what} data.",
                       QUERY_FAILED.format("cluster health"))
    m = _metric(data, score_key, metric)
    if not m:
        return _result(domain, "blind", None, f"RSC reports no {what} data for this tenant.", NOT_REPORTED)
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
        return _result(dom, "blind", None, "RSC returned no threat monitoring data.",
                       QUERY_FAILED.format("threat monitoring"))
    shares, parts = [], []
    # Same roots as rule T-1: Rubrik clusters plus cloud and SaaS accounts. Clusters RSC could not read are not in
    # the total (see notAssessed), so a disconnected cluster is neither credited nor counted as off.
    named = {n: r for n, r in (threat.get("roots") or {}).items()
             if isinstance(r, dict) and not _is_stub(r) and r.get("total")}
    roots = list(named.values())
    if roots:
        # One share for the score, but the evidence reports clusters and accounts separately.
        en, tot = sum(r["threatMonitoringEnabled"] for r in roots), sum(r["total"] for r in roots)
        shares.append(min(1.0, en / tot))
        cdm = named.get("CDM_CLUSTER")
        cloud = [r for n, r in named.items() if n != "CDM_CLUSTER"]
        if cdm:
            parts.append(f"{cdm['threatMonitoringEnabled']} of {cdm['total']} Rubrik clusters")
        if cloud:
            parts.append(f"{sum(r['threatMonitoringEnabled'] for r in cloud)} of "
                         f"{sum(r['total'] for r in cloud)} cloud and SaaS accounts")
    # threatMonitoringObjectEnablementStats is deliberately not scored: its enabled count can exceed its supported
    # count (tenant-wide, unexplained), so any share built from it would be a guess.
    if not shares:
        return _result(dom, "blind", None, "Threat monitoring is not reporting on any account.",
                       NOTHING_LISTED)
    share = sum(shares) / len(shares)
    return _result(dom, _classify(share), share, "Threat monitoring is on for " + "; ".join(parts) + ".")


def hunt_note(data, status=None):
    """One unscored line on threat hunt history, or None when there is nothing reliable to say.

    Hunting is an on-demand action for an incident, so having run none is not a gap. This is a conversation
    prompt, not a finding: it never touches a score, a card or the headline."""
    status = status if status is not None else data.get("_status") or {}
    if _section(data, status, "detection") != "ok":
        return None
    det = data.get("detection")
    h = det.get("hunts") if isinstance(det, dict) else None
    if not isinstance(h, dict) or _is_stub(h):
        return None
    total, latest = h.get("total") or 0, (h.get("latest") or "")[:10]
    if total <= 0:
        return "No threat hunt has been run on this tenant."
    when = f"; the most recent started on {latest}" if latest else ""
    return f"{total} threat hunt{'s have' if total != 1 else ' has'} been run on this tenant{when}."


_FUNCS = {"Anomaly Detection": anomaly, "Threat Monitoring": monitoring, "Sensitive Data Discovery": sensitive}


def compute(data, status=None):
    """{domain: result} for the four capabilities, in display order."""
    status = status if status is not None else data.get("_status") or {}
    return {d: _FUNCS[d](data, status) for d in DOMAINS}


def ceilings(caps):
    """{domain: (score, fixer ids)} for capabilities scoring under 100. Used by the roadmap projection."""
    return {d: (c["score"], FIXERS[d]) for d, c in caps.items() if c["score"] is not None and c["score"] < 100}
