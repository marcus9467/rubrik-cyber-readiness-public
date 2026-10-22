"""Archive storage: bytes consumed per archive target, and the Rubrik Cloud Vault (RCV) entitlement.

`targets` lists every archive target with its type and the bytes stored on it. RCV targets sit outside the
customer's own cloud tenancy; AWS, Azure and GCP targets sit inside it. READ_ONLY targets are read-only mounts of
another cluster's archive, so they would count the same bytes twice. They are kept in the list, flagged, and left
out of every total.

`rcvAccountEntitlement` gives purchased and used RCV capacity in TB per tier. The two queries fail separately: if
one errors the other is still recorded, and the error is stored where the data would be.
"""

TARGETS_Q = """
query Targets($after: String) {
  targets(after: $after, first: 200) {
    count
    nodes { id name targetType consumedBytes status }
    pageInfo { hasNextPage endCursor }
  }
}
"""

ENTITLEMENT_Q = """
query {
  rcvAccountEntitlement {
    entitlements {
      usedCapacity
      entitlement { capacity tier isReplaced expirationDate }
    }
  }
}
"""

READ_ONLY = "READ_ONLY"


def _targets(client):
    nodes = client.paginate(TARGETS_Q, "targets")
    return [{"id": n.get("id"), "name": n.get("name"), "type": n.get("targetType"),
             "bytes": n.get("consumedBytes"), "status": n.get("status"),
             "readOnly": n.get("status") == READ_ONLY} for n in nodes]


def _entitlements(client):
    rows = client.query(ENTITLEMENT_Q)["rcvAccountEntitlement"].get("entitlements") or []
    out = []
    for r in rows:
        e = r.get("entitlement") or {}
        out.append({"tier": e.get("tier"), "capacityTb": e.get("capacity"), "usedTb": r.get("usedCapacity"),
                    "replaced": bool(e.get("isReplaced")), "expires": e.get("expirationDate")})
    return out


def _attempt(fn, client):
    try:
        return fn(client)
    except Exception as e:  # one query failing must not blank the other
        return {"error": str(e)[:300]}


def collect(client):
    return {"targets": _attempt(_targets, client), "entitlements": _attempt(_entitlements, client)}
