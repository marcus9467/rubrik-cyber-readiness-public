# Read-only access for the assessment

**Status: built-in "Read-only Administrator" confirmed on one live tenant (2026-10-22).** Preflight reported
`all collectors can read` with that role and nothing added. The custom-role table in Option 2 is still inferred
from permission names and has not been run with a narrow role.

## Option 1 (recommended): built-in "Read-only Administrator"

RSC ships this role. It is the simplest thing to hand the customer, and it needs no custom role design. Run
preflight with the real account; it names every query that was denied.

## The toolkit is read-only

Every operation is a GraphQL `query`. There are no mutations or subscriptions in the shipped code, and
`tests/test_read_only.py` fails the build if one is added. The role needs no permission that changes anything.

**Do not grant `MANAGE_AUTH_DOMAIN` ("Manage LDAP and SSO").** An earlier version read the full identity
provider record (`allCurrentOrgIdentityProviders`), and one of its fields was denied without that permission.
The toolkit now asks only `hasIdpConfigured`, a yes or no, which Read-only Administrator can run.

## Option 2: custom role with view permissions only

Create a role containing these view permissions. The mapping to collectors is my inference from the
permission names, not something I verified.

| Collector | Permissions likely needed |
|---|---|
| identity, access | VIEW_USER, VIEW_USER_MANAGEMENT, VIEW_ROLE, VIEW_SERVICE_ACCOUNT, VIEW_ACCESS, VIEW_SECURITY_SETTINGS, VIEW_SECURITY_POLICY. Not MANAGE_AUTH_DOMAIN. |
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

Do not add any permission that does not start with VIEW. The toolkit only runs queries. If a query is denied for
a `MANAGE_` permission, that is a bug in the toolkit; report it rather than granting the permission.

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
