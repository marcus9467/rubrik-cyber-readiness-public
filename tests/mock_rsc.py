"""Tiny fake RSC for parity-testing the Python and PowerShell collectors.

Usage: python3 tests/mock_rsc.py PORT   (writes service-account JSON to tests/.mock-sa.json)
Answers by substring match on the query text. Paginates `vSphereVmNewConnection` over two pages and denies
`effectivePermissions` when MOCK_DENY_PERMS=1, so both the happy path and the fallback path can be exercised.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PAGE = lambda nodes, more=False, cur=None: {"count": len(nodes), "nodes": nodes,
                                           "pageInfo": {"hasNextPage": more, "endCursor": cur}}

USERS = [
    {"id": "u-1", "email": "jane.doe@acme.example", "domain": "LOCAL", "status": "ACTIVE", "isAccountOwner": True,
     "lastLogin": "2026-10-01T12:30:45.123Z",
     "totpStatus": {"isEnabled": False, "isEnforced": False, "isEnforcedUserLevel": False, "isSupported": True,
                    "mfaStatus": "NONE"},
     "roles": [{"id": "r-2", "name": "Administrator", "isReadOnly": False, "isOrgAdmin": True}]},
    {"id": "u-2", "email": "bob@acme.example", "domain": "SSO", "status": "ACTIVE", "isAccountOwner": False,
     "lastLogin": None, "totpStatus": None,
     "roles": [{"id": "r-1", "name": "Acme Helpdesk", "isReadOnly": False, "isOrgAdmin": False}]},
]


def vm(name, sla, folder="prod-folder", cluster="c-a", tags=None):
    return {"name": name, "isRelic": False, "templateType": "VM",
            "effectiveSlaDomain": {"id": sla, "name": "x"},
            "logicalPath": [{"name": "vc01.acme.example", "objectType": "VSphereVCenter"},
                            {"name": folder, "objectType": "VSphereFolder"}],
            "vsphereTagPath": [], "allTags": tags or [], "cluster": {"name": cluster}}


VMS_1 = [vm("web01", "00000000-0000-0000-0000-000000000002"), vm("app-test-02", "UNPROTECTED"),
         vm("db01", "UNPROTECTED", folder="UAT servers")]
VMS_2 = [vm("web01", "UNPROTECTED", cluster="c-b"), vm("web01", "00000000-0000-0000-0000-000000000002", cluster="c-b"),
         dict(vm("old", "UNPROTECTED"), isRelic=True), dict(vm("tmpl", "UNPROTECTED"), templateType="TEMPLATE"),
         vm("cache", "UNPROTECTED", tags=[{"key": "env", "value": "dev"}])]

SLA = lambda i, n, **k: {"id": i, "name": n, "isRetentionLockedSla": False, "retentionLockMode": "NONE",
                        "protectedObjectCount": 0, "objectTypes": ["VSPHERE_OBJECT_TYPE"], "isDefault": False,
                        "isArchived": False, "archivalSpecs": [], "replicationSpecsV2": [],
                        "baseFrequency": {"duration": 1, "unit": "DAYS"}, **k}
SLAS = [
    {"id": "UNPROTECTED", "name": "Unprotected"},
    SLA("s-1", "Gold", isRetentionLockedSla=True, retentionLockMode="COMPLIANCE", protectedObjectCount=40,
        archivalSpecs=[{"isComplianceImmutabilityEnabled": True, "threshold": 1, "thresholdUnit": "DAYS",
                        "archivalLocationToClusterMapping": [{"location": {"name": "s3-a", "targetType": "AWS"}}]}],
        replicationSpecsV2=[{"retentionDuration": {"duration": 30, "unit": "DAYS"}, "cluster": {"name": "c-b"},
                             "targetMapping": {"targetType": "CDM"}}]),
    SLA("s-2", "Bronze", protectedObjectCount=12),
    SLA("s-3", "Unused"),
    SLA("s-4", "Old", isArchived=True, protectedObjectCount=5),
]

CLUSTERS = [
    {"id": "c-a", "name": "philly-01", "version": "9.3.1", "type": "ONPREM", "productType": "CDM",
     "status": "Connected", "isHealthy": True, "encryptionEnabled": True, "isAirGapped": False, "isTprEnabled": None,
     "isClusterRemovalTprEnabled": False, "isTunnelEnabled": True, "eosStatus": "OK", "eosDate": None,
     "estimatedRunway": 400, "cyberEventLockdownMode": None, "lastConnectionTime": "2026-10-18T01:02:03.000Z"},
    {"id": "c-b", "name": "nyc-01", "version": "9.2.0", "type": "ONPREM", "productType": "CDM",
     "status": "Disconnected", "isHealthy": False, "encryptionEnabled": False, "isAirGapped": True,
     "isTprEnabled": True, "isClusterRemovalTprEnabled": None, "isTunnelEnabled": False, "eosStatus": "SOON",
     "eosDate": "2027-01-01", "estimatedRunway": None, "cyberEventLockdownMode": None, "lastConnectionTime": None},
]

HOOKS = [
    {"id": "h1", "name": "siem", "status": "ENABLED", "providerType": "CUSTOM",
     "lastFailedErrorInfo": {"statusCode": 0, "errorMessage": None},
     "subscriptionType": {"auditSubscription": {"isSubscribedToAllAudits": True, "auditTypes": []},
                          "eventSubscription": {"isSubscribedToAllEvents": False, "eventTypes": ["Anomaly"],
                                                "severities": ["SEVERITY_CRITICAL"],
                                                "templateInfo": {"templateId": "t1", "customTemplate": None}}}},
    {"id": "h2", "name": "pd", "status": "ENABLED", "providerType": "PAGERDUTY",
     "lastFailedErrorInfo": {"statusCode": 500, "errorMessage": "boom"},
     "subscriptionType": {"auditSubscription": None,
                          "eventSubscription": {"isSubscribedToAllEvents": True, "eventTypes": [],
                                                "severities": ["SEVERITY_CRITICAL", "SEVERITY_WARNING"],
                                                "templateInfo": {"templateId": "t2", "customTemplate": "has eventInfo"}}}},
    {"id": "h3", "name": "off", "status": "DISABLED", "providerType": "CUSTOM", "lastFailedErrorInfo": None,
     "subscriptionType": None},
]


def answer(q, v):
    if "mfaSetting" in q:
        return {"mfaSetting": {"isTotpEnforcedGlobal": False, "isTotpGlobalEnforceLocked": False,
                               "isTotpMandatory": False, "mandatoryTotpEnforcementDate": "2026-12-01T00:00:00.000Z",
                               "mfaRememberHours": 24, "totpReminderHours": 12}}
    if "emailConfig" in q:
        return {"usersInCurrentAndDescendantOrganization": PAGE(
            # emailConfig is a list on a real tenant (verified live): [] means no digest.
            [{"isEmailEnabled": True, "emailConfig": [{"digestId": "d"}]},
             {"isEmailEnabled": False, "emailConfig": []}, {"isEmailEnabled": None, "emailConfig": None}])}
    if "usersInCurrentAndDescendantOrganization" in q:
        return {"usersInCurrentAndDescendantOrganization": PAGE(USERS)}
    if "currentUser" in q:
        return {"currentUser": {"allOrgs": []}}
    if "customTprPolicies" in q:
        return {"customTprPolicies": PAGE([{"policyId": "p-1", "policyName": "Lock", "orgId": "org-1",
                                            "orgName": "global", "quorumRequirement": 1, "numberOfObjectTypes": 2,
                                            "numberOfProtectableObjects": 9}])}
    if "tprConfiguration" in q:
        return {"tprConfiguration": {"isTprEnabled": True, "staticQuorumRequirement": 2, "requestTimeoutHours": 24,
                                     "executionMaxTimeoutHours": 48, "reminderHours": 6}}
    if "dataProtectionCoverageSummary" in q:
        cov = lambda c, p, s: {"platformCategory": c, "protectedObjectsCount": p, "supportedObjectsCount": s,
                               "protectionPercentCoverage": 50.5, "violatedSensitiveObjects": 0}
        return {"dataProtectionCoverageSummary": {"overallProtectionCoverage": cov("ALL", 10, 20),
                                                  "platformCoverage": [cov("VMWARE", 6, 9), cov("CLOUD", 4, 11)]}}
    if "snappableConnection(first:1" in q:
        f = v["f"]
        n = {("ACTIVE",): 100, ("RELIC",): 7, ("ARCHIVED",): 3}.get(tuple(f["objectState"]), 0)
        if "protectionStatus" in f:
            n = {"Protected": 80, "NoSla": 15, "DoNotProtect": 5}[f["protectionStatus"][0]]
        return {"snappableConnection": {"count": n}}
    if "snappableConnection" in q:
        rows = [{"id": "o-1", "name": "acme-epic-db01", "objectType": "VmwareVm", "location": "vc01/dc/folder",
                 "protectionStatus": "NoSla", "complianceStatus": "NOT_APPLICABLE", "logicalBytes": 1000,
                 "cluster": {"id": "c-a", "name": "philly-01"}},
                {"id": "o-1", "name": "acme-epic-db01", "objectType": "VmwareVm", "location": "vc01/dc/folder",
                 "protectionStatus": "NoSla", "complianceStatus": "NOT_APPLICABLE", "logicalBytes": 1000,
                 "cluster": {"id": "c-b", "name": "nyc-01"}},
                {"id": "o-2", "name": "qa-share", "objectType": "NasShare", "location": "/",
                 "protectionStatus": "DoNotProtect", "complianceStatus": "NOT_APPLICABLE", "logicalBytes": None,
                 "cluster": None}]
        return {"snappableConnection": PAGE(rows)}
    if "vSphereVmNewConnection" in q:
        if v.get("after") is None:
            return {"vSphereVmNewConnection": PAGE(VMS_1, True, "p2")}
        return {"vSphereVmNewConnection": PAGE(VMS_2)}
    if "allDhrcScores" in q:
        m = lambda n: {"metric": n, "value": 1.5, "maxValue": 2, "weight": 1, "impact": "HIGH", "version": "1"}
        return {"allDhrcScores": [
            {"category": "PROTECTION", "value": 71.26, "calculatedAt": "x", "date": "2026-10-10T00:00:00.000Z",
             "earliestMetric": None, "context": {"metrics": [m("a")]}},
            {"category": "PROTECTION", "value": 80.04, "calculatedAt": "x", "date": "2026-10-17T00:00:00.000Z",
             "earliestMetric": None, "context": {"metrics": [m("b"), m("c")]}},
            {"category": "SECURITY", "value": 55.0, "calculatedAt": "x", "date": "2026-10-17T00:00:00.000Z",
             "earliestMetric": None, "context": None}]}
    if "slaDomains" in q and "archivalLocationToClusterMapping" in q:
        return {"slaDomains": PAGE([s for s in SLAS])}
    if "slaDomains" in q:
        return {"slaDomains": PAGE(SLAS)}
    if "ipWhitelist" in q:
        return {"ipWhitelist": {"enabled": True, "mode": "ALLOW", "ipCidrs": ["10.20.30.0/24", "203.0.113.7"]}}
    if "lockoutConfig" in q:
        return {"lockoutConfig": {"isBruteForceLockoutEnabled": True, "loginAttemptsLimit": 5,
                                  "isAutoUnlockFeatureEnabled": False, "accountAutoUnlockDurationInMins": None,
                                  "inactiveLockoutConfig": None}}
    if "userSessionManagementConfig" in q:
        return {"userSessionManagementConfig": {"config": {"isInactivityTimeoutEnabled": True,
                "inactivityTimeoutInSeconds": 900, "sessionTimeoutInSeconds": 3600,
                "isConcurrentSessionLimitationEnabled": False, "maxConcurrentSessions": 0,
                "isGlobalPolicyEnforced": True}}}
    if "passwordComplexityPolicy" in q:
        raise PermissionError("VIEW_SECURITY_POLICY denied for host vc01.acme.example")
    if "allCurrentOrgIdentityProviders" in q:
        return {"allCurrentOrgIdentityProviders": [{"name": "ACME Okta", "isDefault": True,
                "allowIdpInitiatedSso": False, "isForceAuthnEnabled": True, "expirationDate": "2027-01-01T00:00:00Z",
                "authorizedGroupsCount": 2, "activeUserCount": 40}]}
    if "serviceAccounts" in q:
        return {"serviceAccounts": {"nodes": [{"name": "veeam-sync", "clientId": "client-abc", "lastLogin": None,
                                               "roles": [{"name": "Administrator"}]}]}}
    if "getAllRolesInOrgConnection" in q:
        if "effectivePermissions" in q and os.environ.get("MOCK_DENY_PERMS") == "1":
            raise PermissionError("VIEW_ROLE denied")
        roles = [{"id": "r-1", "name": "Acme Helpdesk", "description": "desk", "isReadOnly": False, "isOrgAdmin": False},
                 {"id": "r-2", "name": "Administrator", "description": None, "isReadOnly": True, "isOrgAdmin": True}]
        if "effectivePermissions" in q:
            roles[0]["effectivePermissions"] = [
                {"operation": "MANAGE_USER", "objectsForHierarchyTypes": [{"snappableType": "X", "objectIds": ["GlobalResource"]}]},
                {"operation": "VIEW_SLA", "objectsForHierarchyTypes": [{"snappableType": "X", "objectIds": ["abc"]}]},
                {"operation": "MANAGE_USER", "objectsForHierarchyTypes": None}]
            roles[1]["effectivePermissions"] = None
        return {"getAllRolesInOrgConnection": PAGE(roles)}
    if "groupsInCurrentAndDescendantOrganization" in q:
        return {"groupsInCurrentAndDescendantOrganization": PAGE([
            {"groupId": "g-1", "groupName": "acme-backup-admins", "domainName": "okta.acme.example",
             "roles": [{"id": "r-2", "name": "Administrator"}], "users": [{"id": "u-1", "domain": "SSO"}] * 4},
            {"groupId": "g-2", "groupName": "none", "domainName": "okta.acme.example", "roles": None, "users": None}])}
    if "clusterConnection" in q and "isHealthy" in q:
        return {"clusterConnection": PAGE(CLUSTERS)}
    if "clusterConnection" in q:
        return {"clusterConnection": PAGE([{k: c[k] for k in ("id", "productType", "status")} for c in CLUSTERS])}
    if "allEnablementItems" in q:
        t = v["type"]
        if t == "GCP_NATIVE_PROJECT":
            raise PermissionError("not licensed")
        items = {"AWS_NATIVE_ACCOUNT": [{"id": "123456789012", "name": "ACME Prod", "isHealthy": True,
                 "threatMonitoringEnabled": True, "dataThreatAnalyticsEnabled": False, "isYaraProcessingEnabled": False}]}
        return {"threatAnalyticsEnablement": {"allEnablementItems": items.get(t, [])}}
    if "threatMonitoringObjectEnablementStats" in q:
        return {"threatMonitoringObjectEnablementStats": {"enabledObjects": 5, "supportedObjects": 50}}
    if "lambdaSettings" in q:
        return {"lambdaSettings": {"anomalyThreshold": 3, "ransomwareThreshold": 5, "isAnomalyAlertEnabled": True}}
    if "threatHunts" in q:
        if "nodes" not in q:
            return {"threatHunts": {"count": 4}}
        if v.get("begin"):
            return {"threatHunts": {"count": 2, "nodes": [{"startTime": "2026-09-30T10:00:00.000Z"},
                                                          {"startTime": None},
                                                          {"startTime": "2026-10-05T08:00:00.000Z"}]}}
        return {"threatHunts": {"count": 4, "nodes": []}}
    if "allWebhookMessageTemplates" in q:
        return {"allWebhookMessageTemplates": [{"id": "t1", "msgType": "x", "templateData": "no payload here"}]}
    if "allWebhooksV2" in q:
        return {"allWebhooksV2": HOOKS}
    if "syslogExportRules" in q:
        return {"syslogExportRules": {"total": 0}}
    if "snmpConfigurations" in q:
        raise PermissionError("snmp denied")
    if "recoveryPlansBasicInfo" in q:
        return {"recoveryPlansBasicInfo": PAGE([
            {"id": "rp1", "name": "AD", "isArchived": False, "recoveryPlanStatus": "CONFIGURED",
             "recoveryPlanType": "CYBER_RECOVERY", "workloadType": "VM", "numChildren": 3,
             "latestRecovery": {"endTime": "2026-09-01T00:00:00.000Z", "recoveryOutcome": "FAILED",
                                "isAdhocRecovery": False},
             "recoverySchedule": {"nextRunTime": "2026-11-01T00:00:00.000Z"}},
            {"id": "rp2", "name": "web", "isArchived": False, "recoveryPlanStatus": "DRAFT",
             "recoveryPlanType": "TEST", "workloadType": "VM", "numChildren": 1, "latestRecovery": None,
             "recoverySchedule": None},
            {"id": "rp3", "name": "gone", "isArchived": True, "recoveryPlanStatus": "CONFIGURED",
             "recoveryPlanType": "TEST", "workloadType": "VM", "numChildren": 1, "latestRecovery": None,
             "recoverySchedule": None}])}
    raise KeyError("mock has no answer for: " + q[:120])


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.endswith("/client_token"):
            return self._send(200, {"access_token": "tok", "expires_in": 3600})
        req = json.loads(raw)
        try:
            return self._send(200, {"data": answer(req["query"], req.get("variables") or {})})
        except PermissionError as e:
            return self._send(200, {"errors": [{"message": str(e)}], "data": None})
        except KeyError as e:
            return self._send(400, {"errors": [{"message": str(e)}]})


if __name__ == "__main__":
    port = int(sys.argv[1])
    Path(__file__).with_name(".mock-sa.json").write_text(json.dumps({
        "client_id": "mock-id", "client_secret": "mock-secret",
        "access_token_uri": f"http://127.0.0.1:{port}/api/client_token"}))
    HTTPServer(("127.0.0.1", port), H).serve_forever()
