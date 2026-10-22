"""Quorum authorization (TPR): global config plus custom policies."""

ORGS_Q = "query { currentUser { allOrgs { id name } } }"

CFG_Q = """
query Tpr($orgId: String!) {
  tprConfiguration(orgId: $orgId) {
    isTprEnabled staticQuorumRequirement requestTimeoutHours
    executionMaxTimeoutHours reminderHours
  }
}
"""

POLICIES_Q = """
query Policies($after: String) {
  customTprPolicies(after: $after) {
    count
    nodes {
      policyId policyName orgId orgName quorumRequirement
      numberOfObjectTypes numberOfProtectableObjects
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def collect(client):
    # A service account can return an empty allOrgs, so also take org ids from the policies.
    orgs = {o["id"]: o["name"] for o in client.query(ORGS_Q)["currentUser"]["allOrgs"]}
    policies = client.paginate(POLICIES_Q, "customTprPolicies")
    for p in policies:
        orgs.setdefault(p["orgId"], p["orgName"])
    config = {oid: client.query(CFG_Q, {"orgId": oid})["tprConfiguration"] for oid in orgs}
    return {"orgs": orgs, "config": config, "policies": policies}
