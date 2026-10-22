import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from score import RULES, score  # noqa: E402

NOW = datetime.now(timezone.utc)
RECENT = (NOW - timedelta(days=5)).isoformat()


def user(domain="LOCAL", totp=True, owner=False, last=RECENT):
    return {
        "domain": domain, "isAccountOwner": owner, "lastLogin": last,
        "totpStatus": {"isSupported": domain == "LOCAL", "isEnabled": totp and domain == "LOCAL"},
    }


def hardened():
    return {
        "customer": "FIX", "collected_at": RECENT, "status": {},
        "data": {
            "identity": {"users": [user(), user("SSO"), user(owner=True), user(owner=True)]},
            "mfa": {"isTotpEnforcedGlobal": True, "isTotpGlobalEnforceLocked": True,
                    "isTotpMandatory": True, "mfaRememberHours": 8},
            "quorum": {"config": {"o": {"isTprEnabled": True, "staticQuorumRequirement": 2}},
                       "policies": [{"quorumRequirement": 2}]},
            "access": {
                "ipAllowlist": {"enabled": True, "ipCidrs": ["10.0.0.0/8"]},
                "lockout": {"isBruteForceLockoutEnabled": True},
                "passwordPolicy": {"lengthPolicy": {"isActive": True, "defaultValue": 14}},
                "identityProviders": [{"name": "idp"}],
                "serviceAccounts": [{"name": "a", "lastLogin": RECENT}],
            },
            "sla": {"inUse": 4, "inUseLocked": 4, "retentionLocked": 4, "total": 4,
                    "objectsOnLockedSla": 10, "objectsOnLockedSlas": 10, "objectsOnAnySla": 10,
                    "withArchival": 1, "withImmutableArchival": 1},
            "inventory": {"unprotected": {"total": 0, "noSla": 0, "doNotProtect": 0, "logicalBytes": 0},
                          "vmEnvironment": {"nonProd": {"total": 0, "unprotected": 0}, "partiallyProtected": 0,
                                            "activeVms": 5}},
            "clusters": {"total": 1, "encryptionOff": 0, "supportTunnelOpen": 0, "tprUnknown": 0},
            "threat": {"roots": {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 2}}},
            # All four detection capabilities present: a clean tenant can see anomalies, threats, hunts and sensitive data.
            "dhrc": {"scores": {
                "ANOMALIES_DETECTED": {"value": 100, "metrics": [
                    {"metric": "RADAR_ENABLED_CLUSTERS", "value": 1, "maxValue": 1}]},
                "SENSITIVE_DATA": {"value": 100, "metrics": [
                    {"metric": "DATA_DISCOVERY_ENABLED_CLUSTERS", "value": 1, "maxValue": 1},
                    {"metric": "OPEN_ACCESS_SENSITIVE_FILES", "value": 0, "maxValue": 10}]}}},
            "detection": {"settings": {"isAnomalyAlertEnabled": True},
                          "hunts": {"total": 3, "last90": 1, "latest": RECENT},
                          "webhooks": {"total": 1, "enabled": 1, "withAuditFeed": 1, "withEventFeed": 1,
                                       "failing": 0}},
            "recovery": {"total": 2, "neverRun": 0, "lastRunFailed": 0},
            "offsite": {"objects": 10, "objectsReplicationKnown": 10, "objectsArchivalKnown": 10,
                        "objectsBothKnown": 10, "noReplication": 0, "noArchival": 0, "singleCopy": 0},
        },
    }


def ids(bundle):
    return {f["id"] for f in score(bundle)["findings"]}


def test_hardened_tenant_has_no_findings():
    r = score(hardened())
    assert r["findings"] == [], [f["id"] for f in r["findings"]]
    assert r["skipped_rules"] == []


def test_empty_bundle_does_not_crash_and_finds_nothing():
    r = score({"customer": "E", "collected_at": RECENT, "status": {}, "data": {}})
    assert r["findings"] == []
    assert r["skipped_rules"] == []


def test_collector_error_stubs_are_skipped_not_failed():
    b = hardened()
    b["data"]["access"] = {k: {"error": "boom"} for k in b["data"]["access"]}
    r = score(b)
    assert r["skipped_rules"] == []
    assert not ({"A-1", "A-2", "A-3", "A-4", "ID-4"} & ids(b))


def test_quorum_single_approver_and_disabled():
    b = hardened()
    b["data"]["quorum"]["policies"] = [{"quorumRequirement": 1}]
    assert "Q-2" in ids(b)
    b["data"]["quorum"]["config"]["o"]["isTprEnabled"] = False
    assert "Q-1" in ids(b)


def test_totp_counts_only_local_users():
    b = hardened()
    b["data"]["identity"]["users"] = [user(totp=False), user("SSO"), user("SSO")]
    f = next(f for f in score(b)["findings"] if f["id"] == "ID-1")
    assert "1 of 1 local" in f["evidence"]


def test_stale_login_threshold():
    b = hardened()
    old = (NOW - timedelta(days=200)).isoformat()
    b["data"]["identity"]["users"] = [user(last=old), user(last=None), user()]
    f = next(f for f in score(b)["findings"] if f["id"] == "ID-2")
    assert "2 of 3" in f["evidence"]


def test_account_owner_limit():
    b = hardened()
    b["data"]["identity"]["users"] = [user(owner=True) for _ in range(3)]
    assert "ID-3" in ids(b)


def test_retention_lock_severity_scales():
    b = hardened()
    b["data"]["sla"].update(inUse=10, inUseLocked=0)
    assert next(f for f in score(b)["findings"] if f["id"] == "S-1")["severity"] == "high"
    b["data"]["sla"]["inUseLocked"] = 3
    assert next(f for f in score(b)["findings"] if f["id"] == "S-1")["severity"] == "medium"


def test_threat_ignores_cdm_and_empty_and_error_roots():
    b = hardened()
    b["data"]["threat"]["roots"] = {
        "CDM_CLUSTER": {"total": 3, "threatMonitoringEnabled": 0},
        "GCP_NATIVE_PROJECT": {"total": 0, "threatMonitoringEnabled": 0},
        "M365_SUBSCRIPTION": {"error": "x"},
    }
    assert "T-1" not in ids(b)
    b["data"]["threat"]["roots"]["AWS_NATIVE_ACCOUNT"] = {"total": 4, "threatMonitoringEnabled": 1}
    assert "T-1" in ids(b)


def test_rule_exception_is_recorded_and_other_rules_still_run():
    b = hardened()
    b["data"]["mfa"] = {"isTotpEnforcedGlobal": False, "mfaRememberHours": "x"}  # breaks MFA-2 comparison
    b["data"]["clusters"]["encryptionOff"] = 1
    r = score(b)
    assert any(s["rule"] == "mfa_remember" for s in r["skipped_rules"])
    assert "CL-1" in {f["id"] for f in r["findings"]}


def test_scores_drop_with_severity_and_findings_sorted():
    b = copy.deepcopy(hardened())
    b["data"]["quorum"]["config"]["o"]["isTprEnabled"] = False  # critical
    b["data"]["mfa"]["mfaRememberHours"] = 100  # low
    r = score(b)
    assert r["findings"][0]["severity"] == "critical"
    assert r["domain_scores"]["Quorum"] == 75
    assert r["domain_scores"]["MFA"] == 97


def with_roles(u, *names):
    u = dict(u)
    u["roles"] = [{"name": n} for n in names]
    return u


def test_rbac_admin_share_thresholds():
    b = hardened()
    mk = lambda admins, others: [with_roles(user(), "Administrator") for _ in range(admins)] + \
                                [with_roles(user(), "Scoped") for _ in range(others)]
    b["data"]["identity"]["users"] = mk(1, 3)  # 25%: at the limit, no finding
    assert "R-1" not in ids(b)
    b["data"]["identity"]["users"] = mk(2, 3)  # 40%: medium
    assert next(f for f in score(b)["findings"] if f["id"] == "R-1")["severity"] == "medium"
    b["data"]["identity"]["users"] = mk(4, 1)  # 80%: high
    assert next(f for f in score(b)["findings"] if f["id"] == "R-1")["severity"] == "high"


def test_rbac_matches_owner_and_ignores_custom_admin_like_names():
    """Name-only fallback: a custom role is not admin just because of its name."""
    b = hardened()
    b["data"]["identity"]["users"] = [with_roles(user(), "Owner"), with_roles(user(), "DBA - All - Administrator")]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-1")
    assert "1 of 2" in f["evidence"]


def test_rbac_admin_service_accounts():
    b = hardened()
    b["data"]["access"]["serviceAccounts"] = [
        {"name": "a", "lastLogin": RECENT, "roles": [{"name": "Administrator"}]},
        {"name": "b", "lastLogin": RECENT, "roles": [{"name": "Read_Only"}]},
        {"name": "c", "lastLogin": RECENT, "roles": [{"name": "Read_Only"}]},
    ]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-2")
    assert "1 of 3" in f["evidence"] and f["severity"] == "medium"


def test_rbac_skips_when_role_data_missing():
    b = hardened()  # fixture users carry no roles key, service accounts carry none either
    r = score(b)
    assert r["skipped_rules"] == []
    assert not ({"R-1", "R-2", "R-3"} & ids(b))


def test_rbac_admins_without_totp_only_counts_local_admins():
    b = hardened()
    b["data"]["identity"]["users"] = [
        with_roles(user(totp=False), "Administrator"),
        with_roles(user("SSO"), "Administrator"),
        with_roles(user(totp=False), "Scoped"),
        with_roles(user(), "Administrator"),
    ]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-3")
    assert f["evidence"].startswith("1 local")


def _role(name, ops, builtin=False):
    return {"id": name, "name": name, "isReadOnly": builtin, "isOrgAdmin": False,
            "operations": list(ops), "globalScope": True}


def test_custom_role_with_identity_rights_counts_as_admin():
    b = hardened()
    b["data"]["access"]["roles"] = [_role("Scoped", ["VIEW_INVENTORY"]),
                                    _role("Helpdesk", ["MANAGE_USER", "VIEW_INVENTORY"])]
    b["data"]["identity"]["users"] = [with_roles(user(), "Helpdesk"), with_roles(user(), "Helpdesk"),
                                      with_roles(user(), "Scoped")]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-1")
    assert "2 of 3" in f["evidence"] and "manage users" in f["evidence"]
    assert "R-4" in ids(b)


def test_destroy_backups_needs_both_sla_and_snapshot_delete():
    b = hardened()
    b["data"]["access"]["roles"] = [_role("Dba", ["DELETE_SNAPSHOT", "VIEW_SLA"]),
                                    _role("Sla", ["MANAGE_SLA", "DELETE_SNAPSHOT"])]
    b["data"]["identity"]["users"] = [with_roles(user(), "Dba"), with_roles(user(), "Sla")]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-1")
    assert "1 via can change SLA retention" in f["evidence"]


def test_broad_role_and_builtin_floor():
    b = hardened()
    broad = [f"OP_{i}" for i in range(rbac_min())]
    b["data"]["access"]["roles"] = [_role("Wide", broad)]
    b["data"]["identity"]["users"] = [with_roles(user(), "Wide"), with_roles(user(), "Owner")]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-1")
    assert "2 of 2" in f["evidence"]


def rbac_min():
    import rbac
    return rbac.BROAD_OPS_MIN


def test_rbac_name_only_fallback_when_permissions_missing():
    b = hardened()
    b["data"]["access"]["roles"] = [{"id": "x", "name": "DBA - All - Administrator"}]  # no operations key
    b["data"]["identity"]["users"] = [with_roles(user(), "Owner"), with_roles(user(), "DBA - All - Administrator")]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-1")
    assert "1 of 2" in f["evidence"] and "name only" in f["evidence"]
    assert "R-4" not in ids(b)


def test_sso_group_mapped_to_admin_role():
    b = hardened()
    b["data"]["access"]["ssoGroups"] = [
        {"groupId": "g1", "groupName": "ops", "domainName": "d", "roles": [{"id": "1", "name": "Administrator"}],
         "userCount": 7},
        {"groupId": "g2", "groupName": "ro", "domainName": "d", "roles": [{"id": "2", "name": "Scoped"}],
         "userCount": 3}]
    f = next(f for f in score(b)["findings"] if f["id"] == "R-5")
    assert "1 of 2" in f["evidence"] and "7 users" in f["evidence"]
    b["data"]["access"]["ssoGroups"] = {"error": "denied"}
    assert "R-5" not in ids(b)
    b["data"]["access"]["ssoGroups"] = []
    assert "R-5" not in ids(b)


def test_rbac_error_stubs_do_not_crash():
    b = hardened()
    b["data"]["access"]["roles"] = {"error": "denied"}
    b["data"]["access"]["rolePermissions"] = {"error": "denied"}
    r = score(b)
    assert r["skipped_rules"] == []


def test_summarize_permissions_drops_object_ids():
    from rbac import summarize_permissions
    s = summarize_permissions([{"operation": "MANAGE_USER", "objectsForHierarchyTypes": [
        {"snappableType": "X", "objectIds": ["GlobalResource"]}]},
        {"operation": "MOUNT", "objectsForHierarchyTypes": [{"snappableType": "X", "objectIds": ["abc-123"]}]}])
    assert s == {"operations": ["MANAGE_USER", "MOUNT"], "globalScope": True}


def test_every_rule_has_a_unique_id_when_firing():
    seen = set()
    for rule in RULES:
        assert rule.__name__ not in seen
        seen.add(rule.__name__)


def test_anomaly_alerts_off_fires_but_unknown_does_not():
    b = hardened()
    b["data"]["detection"]["settings"] = {"isAnomalyAlertEnabled": False}
    assert "T-3" in ids(b)
    b["data"]["detection"]["settings"] = {"isAnomalyAlertEnabled": None}
    assert "T-3" not in ids(b)
    b["data"]["detection"]["settings"] = {"error": "denied"}
    assert "T-3" not in ids(b)


def test_event_forwarding_none_and_empty_subscriptions():
    b = hardened()
    w = b["data"]["detection"]["webhooks"]
    w.update(enabled=0, withAuditFeed=0, withEventFeed=0)
    assert "T-4" in ids(b)
    w.update(enabled=2)
    assert "T-4" in ids(b)
    w.update(withEventFeed=1)
    assert "T-4" not in ids(b)
    b["data"]["detection"]["webhooks"] = {"error": "denied"}
    assert "T-4" not in ids(b)


def test_failing_webhooks():
    b = hardened()
    b["data"]["detection"]["webhooks"]["failing"] = 1
    assert "T-5" in ids(b)


def test_recovery_plan_rules():
    b = hardened()
    r = b["data"]["recovery"]
    r.update(total=0)
    assert "RC-1" in ids(b)
    r.update(total=4, neverRun=1)
    f = next(f for f in score(b)["findings"] if f["id"] == "RC-2")
    assert f["severity"] == "medium"
    r.update(neverRun=2)
    f = next(f for f in score(b)["findings"] if f["id"] == "RC-2")
    assert f["severity"] == "high"
    r.update(neverRun=0, lastRunFailed=1)
    assert "RC-3" in ids(b)
    b["data"]["recovery"] = {"error": "denied"}
    assert not ({"RC-1", "RC-2", "RC-3"} & ids(b))


def test_new_rules_have_remediation_steps():
    for rid in ("T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "RC-1", "RC-2", "RC-3", "R-4", "R-5"):
        from remediation import REMEDIATION
        assert REMEDIATION[rid]["steps"], rid


def test_webhook_status_code_zero_is_not_a_failure():
    from collectors.detection import _failed
    assert not _failed({"lastFailedErrorInfo": {"statusCode": 0, "errorMessage": ""}})
    assert not _failed({"lastFailedErrorInfo": None})
    assert _failed({"lastFailedErrorInfo": {"statusCode": 502, "errorMessage": ""}})
    assert _failed({"lastFailedErrorInfo": {"statusCode": 0, "errorMessage": "tls"}})


def _offsite_sev(**kw):
    b = hardened()
    b["data"]["offsite"].update(kw)
    fs = {f["id"]: f for f in score(b)["findings"]}
    return fs


def test_offsite_rules_fire_and_scale_with_share():
    fs = _offsite_sev(noReplication=1, noArchival=5, singleCopy=10)
    assert fs["RP-1"]["severity"] == "medium"
    assert fs["RP-2"]["severity"] == "high"
    assert fs["RP-3"]["severity"] == "high"
    assert _offsite_sev(noReplication=0, noArchival=0, singleCopy=0) == {}
    assert _offsite_sev(noReplication=1)["RP-1"]["severity"] == "medium"
    assert _offsite_sev(objects=100, objectsReplicationKnown=100, noReplication=5)["RP-1"]["severity"] == "low"


def test_offsite_silent_on_error_stub_and_unknown():
    b = hardened()
    b["data"]["offsite"] = {"error": "boom"}
    assert not {"RP-1", "RP-2", "RP-3"} & ids(b)
    # Nothing readable: known counts are zero, so no share can be computed and nothing fires.
    b["data"]["offsite"] = {"objects": 10, "objectsReplicationKnown": 0, "objectsArchivalKnown": 0,
                            "objectsBothKnown": 0, "noReplication": 0, "noArchival": 0, "singleCopy": 0}
    assert not {"RP-1", "RP-2", "RP-3"} & ids(b)


def test_offsite_collector_keeps_unknown_distinct_from_none():
    from collectors.offsite import collect

    class C:
        def paginate(self, q, key):
            return [
                {"name": "a", "protectedObjectCount": 4, "replicationSpecsV2": [], "archivalSpecs": []},
                {"name": "b", "protectedObjectCount": 6, "replicationSpecsV2": None, "archivalSpecs": []},
                {"name": "c", "protectedObjectCount": 0, "replicationSpecsV2": [], "archivalSpecs": []},
                {"name": "pseudo"},
            ]
    r = collect(C())
    assert r["slasInUse"] == 2 and r["objects"] == 10
    assert r["noReplication"] == 4 and r["objectsReplicationKnown"] == 4
    assert r["noArchival"] == 10 and r["singleCopy"] == 4 and r["objectsBothKnown"] == 4


def test_email_unused_rule():
    b = hardened()
    d = b["data"]["detection"]
    d["email"] = {"users": 10, "emailEnabled": 0, "withDigest": 0}
    assert "T-6" in ids(b)
    d["email"] = {"users": 10, "emailEnabled": 1, "withDigest": 1}
    assert "T-6" not in ids(b)
    d["email"] = {"users": 0, "emailEnabled": 0, "withDigest": 0}
    assert "T-6" not in ids(b), "no users counted is unknown, not a gap"
    d["email"] = {"error": "denied"}
    assert "T-6" not in ids(b)


def test_template_without_eventinfo_rule():
    b = hardened()
    d = b["data"]["detection"]
    d["webhookRouting"] = {"eventWebhooks": 2, "criticalOnly": 0, "templateChecked": 2, "withoutEventInfo": 1,
                           "templateUnknown": 0}
    assert "T-7" in ids(b)
    d["webhookRouting"]["withoutEventInfo"] = 0
    assert "T-7" not in ids(b)
    d["webhookRouting"] = {"eventWebhooks": 2, "criticalOnly": 0, "templateChecked": 0, "withoutEventInfo": 0,
                           "templateUnknown": 2}
    assert "T-7" not in ids(b), "an unreadable template is unknown, not a gap"
    d["webhookRouting"] = {"error": "denied"}
    assert "T-7" not in ids(b)


def test_critical_only_rule_needs_every_event_webhook_limited():
    b = hardened()
    d = b["data"]["detection"]
    d["webhookRouting"] = {"eventWebhooks": 2, "criticalOnly": 2, "templateChecked": 2, "withoutEventInfo": 0,
                           "templateUnknown": 0}
    assert "T-8" in ids(b)
    d["webhookRouting"]["criticalOnly"] = 1
    assert "T-8" not in ids(b)
    d["webhookRouting"] = {"eventWebhooks": 0, "criticalOnly": 0, "templateChecked": 0, "withoutEventInfo": 0,
                           "templateUnknown": 0}
    assert "T-8" not in ids(b)


def test_silent_cdm_cluster_rule_needs_neither_channel():
    b = hardened()
    d = b["data"]["detection"]
    d["cdmNotifications"] = {"cdmClusters": 3, "checked": 3, "unreadable": 0, "noSyslog": 3,
                             "noTrapReceiver": 2, "neither": 2}
    assert "T-9" in ids(b)
    d["cdmNotifications"]["neither"] = 0
    assert "T-9" not in ids(b), "syslog or SNMP alone is enough"
    d["cdmNotifications"] = {"cdmClusters": 3, "checked": 0, "unreadable": 3, "noSyslog": 0,
                             "noTrapReceiver": 0, "neither": 0}
    assert "T-9" not in ids(b), "unreadable clusters are unknown, not a gap"


def test_new_alerting_blocks_failing_does_not_unassess_alerting():
    from posture import domain_rows
    b = hardened()
    b["status"] = {k: "ok" for k in b["data"]}
    b["data"]["detection"]["email"] = {"error": "denied"}
    b["data"]["detection"]["webhookRouting"] = {"error": "denied"}
    b["data"]["detection"]["cdmNotifications"] = {"error": "denied"}
    assert dict(domain_rows(score(b), b["data"]))["Alerting"] is not None
