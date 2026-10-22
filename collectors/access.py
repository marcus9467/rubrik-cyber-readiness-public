"""Access controls: IP allowlist, password policy, lockout, sessions, SSO, roles, service accounts.

Each sub-query is isolated: an unsupported or unauthorized setting records an error string
for that key and the rest still collect.
"""
from rbac import summarize_permissions

QUERIES = {
    "ipAllowlist": ("query { ipWhitelist { enabled mode ipCidrs } }", "ipWhitelist"),
    "lockout": (
        """query { lockoutConfig {
          isBruteForceLockoutEnabled loginAttemptsLimit isAutoUnlockFeatureEnabled
          accountAutoUnlockDurationInMins
          inactiveLockoutConfig { isInactiveLockoutEnabled inactivityDaysLimit }
        } }""",
        "lockoutConfig",
    ),
    "session": (
        """query { userSessionManagementConfig { config {
          isInactivityTimeoutEnabled inactivityTimeoutInSeconds sessionTimeoutInSeconds
          isConcurrentSessionLimitationEnabled maxConcurrentSessions isGlobalPolicyEnforced
        } } }""",
        "userSessionManagementConfig.config",
    ),
    "passwordPolicy": (
        """query { passwordComplexityPolicy {
          lengthPolicy { defaultValue isActive minValue }
          uppercasePolicy { defaultValue isActive }
          lowercasePolicy { defaultValue isActive }
          numericPolicy { defaultValue isActive }
          specialCharsPolicy { defaultValue isActive }
          passwordExpirationPolicy { defaultValue isActive }
          passwordReusePolicy { defaultValue isActive }
          leakedDetectionPolicy { isActive }
        } }""",
        "passwordComplexityPolicy",
    ),
    # A boolean, not allCurrentOrgIdentityProviders: the full provider record includes fields that need the
    # "Manage LDAP and SSO" permission (MANAGE_AUTH_DOMAIN), and rule A-3 only asks whether any provider exists.
    "hasIdp": ("query { hasIdpConfigured }", "hasIdpConfigured"),
    "serviceAccounts": (
        "query { serviceAccounts { nodes { name clientId lastLogin roles { name } } } }",
        "serviceAccounts.nodes",
    ),
}

ROLES_Q = """
query Roles($after: String) {
  getAllRolesInOrgConnection(after: $after, first: 200) {
    count
    nodes { id name description isReadOnly isOrgAdmin }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Same query plus each role's effective permissions (operation + object scope). Needs permission to read roles.
ROLES_PERMS_Q = """
query Roles($after: String) {
  getAllRolesInOrgConnection(after: $after, first: 200) {
    count
    nodes {
      id name description isReadOnly isOrgAdmin
      effectivePermissions { operation objectsForHierarchyTypes { snappableType objectIds } }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# SSO groups and the roles they carry. `users` lists group members who have logged in to the account.
GROUPS_Q = """
query Groups($after: String) {
  groupsInCurrentAndDescendantOrganization(after: $after, first: 100, shouldIncludeGroupsWithoutRole: true) {
    count
    nodes { groupId groupName domainName roles { id name } users { id domain } }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def _dig(data, path):
    for key in path.split("."):
        data = data[key]
    return data


def collect(client):
    out = {}
    for key, (gql, path) in QUERIES.items():
        try:
            out[key] = _dig(client.query(gql), path)
        except Exception as e:
            out[key] = {"error": str(e)[:300]}
    try:
        roles = client.paginate(ROLES_PERMS_Q, "getAllRolesInOrgConnection")
        for r in roles:
            r.update(summarize_permissions(r.pop("effectivePermissions", None)))
        out["roles"] = roles
    except Exception as e:
        # Permissions unreadable: fall back to names only (scoring then uses the built-in name floor).
        try:
            out["roles"] = client.paginate(ROLES_Q, "getAllRolesInOrgConnection")
        except Exception as e2:
            out["roles"] = {"error": str(e2)[:300]}
        out["rolePermissions"] = {"error": str(e)[:300]}
    try:
        groups = client.paginate(GROUPS_Q, "groupsInCurrentAndDescendantOrganization")
        out["ssoGroups"] = [
            {"groupId": g["groupId"], "groupName": g["groupName"], "domainName": g["domainName"],
             "roles": [{"id": r["id"], "name": r["name"]} for r in g.get("roles") or []],
             "userCount": len(g.get("users") or [])}
            for g in groups]
    except Exception as e:
        out["ssoGroups"] = {"error": str(e)[:300]}
    return out
