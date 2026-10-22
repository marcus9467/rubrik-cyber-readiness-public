"""Identity posture: users, TOTP, roles, last login, lockout."""

USERS_Q = """
query Users($after: String) {
  usersInCurrentAndDescendantOrganization(
    after: $after
    filter: {emailFilter: "", lockoutStateFilter: ALL, hiddenStateFilter: NOT_HIDDEN}
    shouldIncludeUserWithoutRole: true
  ) {
    count
    nodes {
      id email domain status isAccountOwner lastLogin
      totpStatus { isEnabled isEnforced isEnforcedUserLevel isSupported mfaStatus }
      roles { id name isReadOnly isOrgAdmin }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def collect(client):
    users = client.paginate(USERS_Q, "usersInCurrentAndDescendantOrganization")
    return {"users": users}
