import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from collectors import detection  # noqa: E402

PD = "{\"summary\": \"{{.Message}}\"}"
CEF = "{\"summary\": \"{{.Message}}\", \"eventInfo\": {{.EventInfo}}}"


def hook(template_id=None, custom=None, severities=("SEVERITY_CRITICAL",), status="ENABLED", all_events=True):
    return {"status": status, "subscriptionType": {"eventSubscription": {
        "isSubscribedToAllEvents": all_events, "eventTypes": [], "severities": list(severities),
        "templateInfo": {"templateId": template_id, "customTemplate": custom}}}}


class Fake:
    def __init__(self, hooks=None, templates=None, users=None, clusters=None, syslog=None, snmp=None,
                 fail_templates=False):
        self.hooks, self.users, self.clusters = hooks or [], users or [], clusters or []
        self.templates = templates if templates is not None else {}
        self.syslog, self.snmp, self.fail_templates = syslog or {}, snmp or {}, fail_templates

    def query(self, gql, variables=None):
        if "allWebhooksV2" in gql:
            return {"allWebhooksV2": self.hooks}
        if "allWebhookMessageTemplates" in gql:
            if self.fail_templates:
                raise RuntimeError("denied")
            if variables["t"] == "CUSTOM":
                return {"allWebhookMessageTemplates": []}
            return {"allWebhookMessageTemplates": [{"id": i, "msgType": "EVENT", "templateData": t}
                                                   for i, t in self.templates.items()]}
        if "syslogExportRules" in gql:
            r = self.syslog[variables["c"]]
            if isinstance(r, Exception):
                raise r
            return {"syslogExportRules": {"total": r}}
        if "snmpConfigurations" in gql:
            return {"snmpConfigurations": self.snmp[variables["c"]]}
        raise AssertionError(gql)

    def paginate(self, gql, key):
        return self.users if key == "usersInCurrentAndDescendantOrganization" else self.clusters


def test_default_pagerduty_template_lacks_eventinfo_and_cef_has_it():
    c = Fake(hooks=[hook(1), hook(3)], templates={1: PD, 3: CEF})
    r = detection.collect_webhook_routing(c)
    assert (r["eventWebhooks"], r["templateChecked"], r["withoutEventInfo"], r["templateUnknown"]) == (2, 2, 1, 0)
    assert r["criticalOnly"] == 2


def test_custom_template_text_is_checked_inline():
    r = detection.collect_webhook_routing(Fake(hooks=[hook(None, custom=CEF), hook(None, custom=PD)]))
    assert (r["templateChecked"], r["withoutEventInfo"]) == (2, 1)


def test_unreadable_templates_are_unknown_not_a_gap():
    r = detection.collect_webhook_routing(Fake(hooks=[hook(1)], fail_templates=True))
    assert (r["templateChecked"], r["withoutEventInfo"], r["templateUnknown"]) == (0, 0, 1)


def test_disabled_and_audit_only_webhooks_are_not_event_webhooks():
    audit_only = hook(1, all_events=False)
    r = detection.collect_webhook_routing(Fake(hooks=[hook(1, status="DISABLED"), audit_only], templates={1: PD}))
    assert r["eventWebhooks"] == 0


def test_warning_severity_means_not_critical_only():
    r = detection.collect_webhook_routing(
        Fake(hooks=[hook(3, severities=("SEVERITY_CRITICAL", "SEVERITY_WARNING"))], templates={3: CEF}))
    assert r["criticalOnly"] == 0


def test_email_counts_are_aggregates_only():
    users = [{"isEmailEnabled": True, "emailConfig": [{"digestId": 1}]},
             {"isEmailEnabled": False, "emailConfig": []}, {"isEmailEnabled": False, "emailConfig": []}]
    assert detection.collect_email(Fake(users=users)) == {"users": 3, "emailEnabled": 1, "withDigest": 1}


def test_cdm_notifications_neither_unreadable_and_non_cdm():
    clusters = [{"id": "a", "productType": "CDM", "status": "Connected"},
                {"id": "b", "productType": "CDM", "status": "Connected"},
                {"id": "c", "productType": "CDM", "status": "Connected"},
                {"id": "d", "productType": "CDM", "status": "Disconnected"},
                {"id": "e", "productType": "POLARIS", "status": "Connected"}]
    snmp = {"a": {"isEnabled": True, "trapReceiverConfigs": []},
            "b": {"isEnabled": True, "trapReceiverConfigs": [{"port": 162}]},
            "c": {"isEnabled": False, "trapReceiverConfigs": [{"port": 162}]}}
    c = Fake(clusters=clusters, syslog={"a": 0, "b": 0, "c": RuntimeError("denied")}, snmp=snmp)
    r = detection.collect_cdm_notifications(c)
    assert r["cdmClusters"] == 3
    assert (r["checked"], r["unreadable"]) == (2, 1)
    assert r["neither"] == 1, "a has no syslog and no trap receiver; b has a trap receiver"
    assert (r["noSyslog"], r["noTrapReceiver"]) == (2, 1)


def test_snmp_community_string_is_never_requested():
    assert "communityString" not in detection.SNMP_Q


def test_collect_isolates_each_new_block():
    class Boom(Fake):
        def query(self, gql, variables=None):
            if "allWebhooksV2" in gql and "templateInfo" in gql:
                raise RuntimeError("denied")
            if "lambdaSettings" in gql:
                return {"lambdaSettings": {"isAnomalyAlertEnabled": True}}
            if "threatHunts" in gql:
                return {"threatHunts": {"count": 0}}
            if "allWebhooksV2" in gql:
                return {"allWebhooksV2": []}
            return super().query(gql, variables)

    out = detection.collect(Boom())
    assert "error" in out["webhookRouting"]
    assert out["settings"] == {"isAnomalyAlertEnabled": True}
    assert "error" not in out["webhooks"] and "items" not in out["webhooks"]
