import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from redact import redact_bundle  # noqa: E402
from score import score  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_score import hardened, user, with_roles  # noqa: E402

EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def sample():
    b = hardened()
    u1 = with_roles(user(totp=False), "Administrator")
    u1.update(id="u-1", email="jane.doe@acme.example")
    u2 = with_roles(user("SSO"), "Owner")
    u2.update(id="u-2", email="bob@acme.example")
    b["data"]["identity"]["users"] = [u1, u2]
    b["data"]["access"]["serviceAccounts"] = [
        {"name": "veeam-sync", "clientId": "client-abc", "lastLogin": None, "roles": [{"name": "Administrator"}]}]
    b["data"]["access"]["ipAllowlist"] = {"enabled": True, "ipCidrs": ["10.20.30.0/24", "203.0.113.7"]}
    b["data"]["access"]["identityProviders"] = [{"name": "ACME Okta"}]
    b["data"]["access"]["roles"] = [
        {"id": "r-1", "name": "Acme Helpdesk", "isReadOnly": False, "operations": ["MANAGE_USER"],
         "globalScope": True},
        {"id": "r-2", "name": "Administrator", "isReadOnly": True, "operations": [], "globalScope": True}]
    b["data"]["access"]["ssoGroups"] = [
        {"groupId": "g-1", "groupName": "acme-backup-admins", "domainName": "okta.acme.example",
         "roles": [{"id": "r-2", "name": "Administrator"}], "userCount": 4}]
    u2["roles"].append({"name": "Acme Helpdesk"})
    b["data"]["quorum"]["orgs"] = {"org-1": "global"}
    b["data"]["quorum"]["policies"] = [{"policyId": "p-1", "policyName": "Example SLA lock", "orgId": "org-1",
                                         "orgName": "global", "quorumRequirement": 1}]
    b["data"]["sla"]["slas"] = [{"id": "s-1", "name": "Example-Epic-Gold"}]
    b["data"]["clusters"]["clusters"] = [{"id": "c-1", "name": "acme-philly-01"}]
    b["data"]["inventory"]["unprotected"]["rows"] = [
        {"id": "o-1", "name": "acme-epic-db01", "location": "vcenter.acme.example", "clusterName": "acme-philly-01"}]
    b["data"]["inventory"]["unprotected"]["byCluster"] = [{"key": "acme-philly-01", "count": 1}]
    b["data"]["inventory"]["unprotected"]["byLocation"] = [{"key": "vcenter.acme.example", "count": 1}]
    b["data"]["inventory"]["vmEnvironment"]["matchedText"] = [{"key": "acme-test-vm", "count": 1}]
    b["data"]["inventory"]["vmEnvironment"]["unprotectedNonProd"] = [
        {"name": "acme-test-vm", "cluster": "acme-philly-01", "signals": [["vmName", "acme-test-vm"]]}]
    b["data"]["threat"]["roots"]["AWS_NATIVE_ACCOUNT"]["items"] = [{"id": "123456789012", "name": "ACME Prod"}]
    b["data"]["access"]["lockout"] = {"error": "HTTP 400 host vcenter.acme.example denied"}
    b["data"]["offsite"] = {"slas": [
        {"name": "Acme-Offsite-Gold", "archiveTargets": [{"name": "acme-glacier-vault"}],
         "replicationTargets": [{"cluster": "acme-dr-site"}]}]}
    b["data"]["recovery"] = {"plans": [{"name": "Acme Payroll Failover"}]}
    return b


SENSITIVE = ["jane.doe", "bob@", "acme", "Acme", "Example", "veeam-sync", "client-abc", "10.20.30", "203.0.113",
             "123456789012", "Okta"]


def test_no_identifying_value_survives():
    red, _ = redact_bundle(sample())
    text = json.dumps(red)
    assert not EMAIL.search(text)
    for s in SENSITIVE:
        assert s not in text, f"leaked: {s}"


def test_input_is_not_modified():
    b = sample()
    before = json.dumps(b, sort_keys=True)
    redact_bundle(b)
    assert json.dumps(b, sort_keys=True) == before


def test_scoring_is_unchanged_by_redaction():
    b = sample()
    red, _ = redact_bundle(b)
    a, r = score(b), score(red)
    assert [f["id"] for f in a["findings"]] == [f["id"] for f in r["findings"]]
    assert a["domain_scores"] == r["domain_scores"]
    assert [f["evidence"] for f in a["findings"]] == [f["evidence"] for f in r["findings"]]


def test_same_value_maps_to_same_pseudonym_and_map_reverses():
    b = sample()
    red, mapping = redact_bundle(b)
    row = red["data"]["inventory"]["unprotected"]["rows"][0]
    assert row["clusterName"] == red["data"]["inventory"]["unprotected"]["byCluster"][0]["key"]
    assert red["data"]["inventory"]["vmEnvironment"]["unprotectedNonProd"][0]["cluster"] == row["clusterName"]
    assert "obj:acme-epic-db01" in mapping["map"]
    assert mapping["map"]["obj:acme-epic-db01"] == row["name"]


def test_two_runs_use_different_salts():
    a, _ = redact_bundle(sample())
    b, _ = redact_bundle(sample())
    assert a["data"]["identity"]["users"][0]["email"] != b["data"]["identity"]["users"][0]["email"]


def test_legacy_webhook_records_are_dropped():
    b = sample()
    b["data"]["detection"]["webhooks"]["items"] = [{"id": 5, "name": "Acme-Sentinel", "status": "ENABLED"}]
    red, _ = redact_bundle(b)
    assert "items" not in red["data"]["detection"]["webhooks"]
    assert "Acme-Sentinel" not in json.dumps(red)
    assert [f["id"] for f in score(b)["findings"]] == [f["id"] for f in score(red)["findings"]]


def test_alerting_aggregates_survive_redaction():
    b = sample()
    d = b["data"]["detection"]
    d["email"] = {"users": 9, "emailEnabled": 0, "withDigest": 0}
    d["webhookRouting"] = {"eventWebhooks": 1, "criticalOnly": 1, "templateChecked": 1, "withoutEventInfo": 1,
                           "templateUnknown": 0}
    d["cdmNotifications"] = {"cdmClusters": 2, "checked": 2, "unreadable": 0, "noSyslog": 2,
                             "noTrapReceiver": 2, "neither": 2}
    red, _ = redact_bundle(b)
    assert red["data"]["detection"]["email"] == d["email"]
    assert red["data"]["detection"]["webhookRouting"] == d["webhookRouting"]
    assert {"T-6", "T-7", "T-8", "T-9"} <= {f["id"] for f in score(red)["findings"]}
