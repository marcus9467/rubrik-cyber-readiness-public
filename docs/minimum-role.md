# Read-only access for the assessment

**Status: untested.** Everything below is inferred from RSC's permission names. It has not been run
against a service account with a narrow role. Run `preflight.py` (see the [README](../README.md)) with the real account; it
names every query that was denied.

## Option 1 (try first): built-in "Read-only Administrator"

RSC ships this role. It is the simplest thing to hand the customer, and it needs no custom role design.
It is not confirmed to cover every query in this toolkit. If preflight reports gaps, use Option 2.

## Option 2: custom role with view permissions only

Create a role containing these view permissions. The mapping to collectors is my inference from the
permission names, not something I verified.

| Collector | Permissions likely needed |
|---|---|
| identity, access | VIEW_USER, VIEW_USER_MANAGEMENT, VIEW_ROLE, VIEW_SERVICE_ACCOUNT, VIEW_ACCESS, VIEW_SECURITY_SETTINGS, VIEW_SECURITY_POLICY |
| mfa, quorum | VIEW_SECURITY_SETTINGS, VIEW_TPR_CONFIGURATION, VIEW_TPR_POLICY, VIEW_TPR_REQUEST, VIEW_ORGANIZATION |
| inventory | VIEW_INVENTORY, VIEW_CLUSTER, VIEW_DASHBOARD |
| sla | VIEW_SLA, VIEW_ARCHIVAL_LOCATION |
| clusters | VIEW_CLUSTER, VIEW_CDM_SYS_CONFIG |
| threat, dhrc | VIEW_ANOMALY_DETECTION_RESULTS, VIEW_THREAT_HUNT_RESULTS, VIEW_DATA_SECURITY_POSTURE_RESULTS, VIEW_DATA_CLASS_GLOBAL, VIEW_FEATURE_ENABLEMENT, VIEW_DASHBOARD |
| detection | **Unknown.** See below. |

## Alerting queries (permissions not identified)

The `detection` collector reads anomaly alert settings, threat hunt history, webhooks and webhook message
templates, per-user email notification settings, and syslog and SNMP configuration on CDM clusters. I have not
identified which VIEW permissions these need, and none of them has been run with a narrow role. Treat them as
untested and rely on `preflight.py`.

Each part is isolated. A denied query is recorded as an error for that part only, the affected rule is skipped,
and the other alerting results still appear. Nothing is ever reported as a gap because a query was denied.

Email settings come from the same user listing the identity collector reads. Syslog and SNMP are read per
connected CDM cluster, so a cluster that is offline is counted as unreadable and skipped.

Scope the role to all objects. A role limited to some hierarchies will make coverage counts understate
what exists, and the report cannot tell the difference.

Do not add any permission that does not start with VIEW. The toolkit only runs queries.

## RBAC permission and SSO group queries (untested with a narrow role)

The role catalogue with effective permissions (`getAllRolesInOrgConnection`) and SSO groups
(`groupsInCurrentAndDescendantOrganization`) were only run with a full-admin lab account. Which VIEW
permissions they need is UNTESTED; VIEW_ROLE and VIEW_USER_MANAGEMENT are the likely ones. If the role
list cannot be read with permissions, the collector falls back to names and records
`access.rolePermissions` as an error stub; an unreadable group list is recorded as `access.ssoGroups`
with an error stub, and rule R-5 is skipped.

## What a denial looks like

A query the role cannot run is recorded as an error for that section. The report marks the affected
area "not assessed" instead of scoring it, so a missing permission never produces a falsely clean score.
Preflight lists each denied section by name.

## Credential handling

- Create a dedicated service account for this assessment and delete it afterwards.
- The JSON file holds a client secret. Keep it out of email and shared folders.
- The toolkit never writes the secret to its output.
