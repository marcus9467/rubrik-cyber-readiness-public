"""Detection and response plumbing: anomaly alerting, ransomware investigation activity, event forwarding."""

SETTINGS_Q = "query { lambdaSettings { anomalyThreshold ransomwareThreshold isAnomalyAlertEnabled } }"

WEBHOOKS_Q = """
query {
  allWebhooksV2 {
    id name status providerType
    lastFailedErrorInfo { statusCode errorMessage }
    subscriptionType {
      auditSubscription { isSubscribedToAllAudits auditTypes }
      eventSubscription { isSubscribedToAllEvents eventTypes }
    }
  }
}
"""


# threatHunts ignores `first` (a tenant with 99 hunts returned all 99 when asked for 6) and a hunt that has not
# started has a null startTime. So ask for counts only where rows are not needed, and take the latest start as the
# max of the non-null values instead of trusting the order.
HUNT_COUNT_Q = "query($begin: DateTime) { threatHunts(beginTime: $begin) { count } }"
HUNT_TOTAL_Q = "query { threatHunts { count } }"
HUNT_ROWS_Q = "query($begin: DateTime) { threatHunts(beginTime: $begin) { count nodes { startTime } } }"
HUNT_WINDOW_DAYS = 90  # only dates the 'last90' count kept in the bundle; hunting is not scored


def collect_hunts(client, now=None):
    """Threat hunt history: total ever, count in the last 90 days, and the most recent start time."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    begin = (now - timedelta(days=HUNT_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    total = client.query(HUNT_TOTAL_Q)["threatHunts"]["count"]
    if not total:
        return {"total": 0, "last90": 0, "latest": None}
    recent = client.query(HUNT_ROWS_Q, {"begin": begin})["threatHunts"]
    starts = [n["startTime"] for n in recent["nodes"] if n.get("startTime")]
    if starts:
        return {"total": total, "last90": recent["count"], "latest": max(starts)}
    # Nothing recent. Only now fetch every row, to date the last hunt that did run.
    allrows = client.query(HUNT_ROWS_Q, {"begin": None})["threatHunts"]["nodes"]
    starts = [n["startTime"] for n in allrows if n.get("startTime")]
    return {"total": total, "last90": 0, "latest": max(starts) if starts else None}


def _failed(h):
    """The lab returns lastFailedErrorInfo {statusCode: 0} for a webhook with no error, so require a real code or message."""
    e = h.get("lastFailedErrorInfo") or {}
    return bool(e.get("errorMessage")) or (e.get("statusCode") or 0) > 0


def collect(client):
    out = {}
    # overallRansomwareInvestigationSummary was tried and returns an internal 500 on the lab tenant; no rule needs it.
    try:
        out["settings"] = client.query(SETTINGS_Q)["lambdaSettings"]
    except Exception as e:
        out["settings"] = {"error": str(e)[:300]}
    try:
        out["hunts"] = collect_hunts(client)
    except Exception as e:
        out["hunts"] = {"error": str(e)[:300]}
    try:
        hooks = client.query(WEBHOOKS_Q)["allWebhooksV2"]
        enabled = [h for h in hooks if str(h.get("status", "")).upper() == "ENABLED"]
        # A subscription object can exist and still select nothing, so look at what it subscribes to.
        def feeds(h, key, all_flag, types_key):
            s = (h.get("subscriptionType") or {}).get(key) or {}
            return bool(s.get(all_flag) or s.get(types_key))
        out["webhooks"] = {
            "total": len(hooks),
            "enabled": len(enabled),
            "withAuditFeed": sum(feeds(h, "auditSubscription", "isSubscribedToAllAudits", "auditTypes")
                                 for h in enabled),
            "withEventFeed": sum(feeds(h, "eventSubscription", "isSubscribedToAllEvents", "eventTypes")
                                 for h in enabled),
            "failing": sum(_failed(h) for h in enabled),
        }
    except Exception as e:
        out["webhooks"] = {"error": str(e)[:300]}
    # Each block below is isolated: a denied field here must never take down T-3 to T-5 above.
    # Only aggregates are stored. Names, URLs, recipients and hostnames never enter the bundle.
    for key, fn in (("webhookRouting", collect_webhook_routing), ("email", collect_email),
                    ("cdmNotifications", collect_cdm_notifications)):
        try:
            out[key] = fn(client)
        except Exception as e:
            out[key] = {"error": str(e)[:300]}
    return out


WEBHOOK_ROUTING_Q = """
query {
  allWebhooksV2 {
    status
    subscriptionType {
      eventSubscription {
        isSubscribedToAllEvents eventTypes severities
        templateInfo { templateId customTemplate }
      }
    }
  }
}
"""
TEMPLATES_Q = "query($t: TemplateRecordType!) { allWebhookMessageTemplates(input: {recordType: $t}) { id msgType templateData } }"
CRITICAL = "SEVERITY_CRITICAL"


def collect_webhook_routing(client):
    """For enabled event webhooks: severity filter and whether the payload template carries eventInfo.

    Threat Monitoring and threat hunting detail only reaches a SIEM when the template includes eventInfo, and the
    default PagerDuty template does not. A template that cannot be read is counted as unknown, never as a gap.
    """
    hooks = client.query(WEBHOOK_ROUTING_Q)["allWebhooksV2"]
    templates = {}
    for kind in ("DEFAULT", "CUSTOM"):
        try:
            for t in client.query(TEMPLATES_Q, {"t": kind})["allWebhookMessageTemplates"]:
                templates[t["id"]] = t.get("templateData") or ""
        except Exception:
            pass  # templates unreadable: webhooks that point at them are counted as unknown below
    event = []
    for h in hooks:
        if str(h.get("status", "")).upper() != "ENABLED":
            continue
        es = (h.get("subscriptionType") or {}).get("eventSubscription") or {}
        if es.get("isSubscribedToAllEvents") or es.get("eventTypes"):
            event.append(es)
    out = {"eventWebhooks": len(event), "criticalOnly": 0, "templateChecked": 0, "withoutEventInfo": 0,
           "templateUnknown": 0}
    for es in event:
        sev = es.get("severities") or []
        if sev and set(sev) == {CRITICAL}:
            out["criticalOnly"] += 1
        ti = es.get("templateInfo") or {}
        text = ti.get("customTemplate") or templates.get(ti.get("templateId"))
        if text is None:
            out["templateUnknown"] += 1
            continue
        out["templateChecked"] += 1
        if "eventinfo" not in text.lower():
            out["withoutEventInfo"] += 1
    return out


EMAIL_Q = """
query Email($after: String) {
  usersInCurrentAndDescendantOrganization(after: $after, first: 200) {
    count
    nodes { isEmailEnabled emailConfig { digestId } }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def collect_email(client):
    """How many users get RSC email. RSC defaults to no email, so a user who was never set up gets none."""
    users = client.paginate(EMAIL_Q, "usersInCurrentAndDescendantOrganization")
    return {"users": len(users),
            "emailEnabled": sum(u.get("isEmailEnabled") is True for u in users),
            "withDigest": sum(bool(u.get("emailConfig")) for u in users)}


CDM_Q = """
query Cdm($after: String) {
  clusterConnection(after: $after, first: 200) { nodes { id productType status } pageInfo { hasNextPage endCursor } }
}
"""
SYSLOG_Q = "query($c: String!) { syslogExportRules(input: {clusterUuid: $c}) { total } }"
# communityString is a credential, so it is never requested. Only whether SNMP and trap receivers exist.
SNMP_Q = ("query($c: String!) { snmpConfigurations(input: {clusterUuid: $c, id: \"me\"}) "
          "{ isEnabled trapReceiverConfigs { port } } }")


def collect_cdm_notifications(client):
    """Per connected CDM cluster: is any syslog export rule or SNMP trap receiver configured.

    A cluster that cannot be read (offline, denied) is counted as unreadable and is never a gap.
    """
    nodes = client.paginate(CDM_Q, "clusterConnection")
    cdm = [c for c in nodes if c.get("productType") == "CDM" and c.get("status") == "Connected"]
    out = {"cdmClusters": len(cdm), "checked": 0, "unreadable": 0, "noSyslog": 0, "noTrapReceiver": 0, "neither": 0}
    for c in cdm:
        try:
            syslog = client.query(SYSLOG_Q, {"c": c["id"]})["syslogExportRules"]["total"] or 0
            snmp = client.query(SNMP_Q, {"c": c["id"]})["snmpConfigurations"]
            traps = len(snmp.get("trapReceiverConfigs") or []) if snmp.get("isEnabled") else 0
        except Exception:
            out["unreadable"] += 1
            continue
        out["checked"] += 1
        out["noSyslog"] += syslog == 0
        out["noTrapReceiver"] += traps == 0
        out["neither"] += syslog == 0 and traps == 0
    return out
