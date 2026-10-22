"""Effective-permission analysis for RBAC rules. Pure functions, no network.

AUTHOR'S JUDGMENT, NOT A RUBRIK-PUBLISHED CLASSIFICATION. The operation names below are values of the
RSC `Operation` GraphQL enum. Which of them count as "admin-equivalent" is a judgment about blast radius,
not something RSC states. Review the sets before showing a customer.

A role is admin-equivalent when ANY of these hold:
  identity_admin  it can create or change users, roles, service accounts or auth domains, which lets the
                  holder grant themselves anything else (privilege escalation).
  quorum_control  it can configure or disable Transparent Protection / quorum (TPR), which removes the
                  approval gate on destructive actions.
  destroy_backups it can both change SLA retention and delete snapshots, which together can erase
                  recovery points (the ransomware end state). Either one alone is not enough: scoped
                  DBA or VM roles routinely hold DELETE_SNAPSHOT on their own workloads.
  broad           it holds BROAD_OPS_MIN or more distinct operations (GUIDANCE: Administrator and Owner
                  hold about 240; the largest scoped role seen in the lab held 87 before the identity
                  operations were counted).
  built-in        name is Administrator or Owner, or RSC marks the role isOrgAdmin (the floor; nothing
                  that matched before can stop matching).
Signals that are recorded but do not make a role admin-equivalent by themselves: snapshot_delete,
sla_retention, quorum_approve (approvers are meant to exist).

Scope is recorded (`globalScope`), not used to decide: a role that can manage users only inside one
suborganization is rare and still worth a human look.
"""

BUILTIN_ADMIN_NAMES = {"Administrator", "Owner"}
BROAD_OPS_MIN = 150  # GUIDANCE

IDENTITY_ADMIN_OPS = {
    "MANAGE_USER", "MANAGE_ROLE", "MANAGE_AUTH_DOMAIN", "EDIT_USER_MANAGEMENT", "ASSIGN_ROLE",
    "MANAGE_ACCESS", "MANAGE_SERVICE_ACCOUNT", "MANAGE_USER_CREDENTIALS",
}
QUORUM_CONTROL_OPS = {"MANAGE_TPR_CONFIGURATION", "MANAGE_TPR_ENABLEMENT", "MANAGE_TPR_POLICY"}
SLA_OPS = {"MANAGE_SLA", "MODIFY_SLA", "DELETE_SLA", "CREATE_SLA"}
SNAPSHOT_DELETE_OPS = {"DELETE_SNAPSHOT"}
QUORUM_APPROVE_OPS = {"APPROVE_TPR_REQUEST"}

SIGNAL_LABELS = {
    "builtin": "built-in admin role",
    "identity_admin": "can manage users/roles/SSO",
    "quorum_control": "can change quorum settings",
    "destroy_backups": "can change SLA retention and delete snapshots",
    "broad": "broad permission set",
}


def summarize_permissions(perms):
    """Collapse a role's effectivePermissions into a small, non-identifying record.

    Object ids are customer data and are dropped; only whether the scope is global/root-level is kept.
    """
    ops, global_scope = set(), False
    for p in perms or []:
        ops.add(p.get("operation"))
        for h in p.get("objectsForHierarchyTypes") or []:
            for oid in h.get("objectIds") or []:
                if oid == "GlobalResource" or str(oid).endswith("_ROOT"):
                    global_scope = True
    ops.discard(None)
    return {"operations": sorted(ops), "globalScope": global_scope}


def role_signals(role):
    """Return the ordered list of signal keys that make this role admin-equivalent (empty = not)."""
    ops = set(role.get("operations") or [])
    sig = []
    if role.get("name") in BUILTIN_ADMIN_NAMES or role.get("isOrgAdmin"):
        sig.append("builtin")
    if ops & IDENTITY_ADMIN_OPS:
        sig.append("identity_admin")
    if ops & QUORUM_CONTROL_OPS:
        sig.append("quorum_control")
    if ops & SLA_OPS and ops & SNAPSHOT_DELETE_OPS:
        sig.append("destroy_backups")
    if len(ops) >= BROAD_OPS_MIN:
        sig.append("broad")
    return sig


def usable_roles(access):
    """The role catalogue if it was collected with permissions, else None (name-only fallback)."""
    roles = (access or {}).get("roles")
    if not isinstance(roles, list) or not roles or "operations" not in roles[0]:
        return None
    return roles


def admin_roles(access):
    """name -> signals for every admin-equivalent role in the catalogue (empty dict if none or unknown)."""
    roles = usable_roles(access)
    return {r["name"]: role_signals(r) for r in roles if role_signals(r)} if roles else {}


def principal_signals(principal, by_name):
    """Signals for one user/service account/group: union over its roles. Built-in name is the floor."""
    out = []
    for r in principal.get("roles", []) or []:
        sig = list(by_name.get(r["name"], []))
        if r["name"] in BUILTIN_ADMIN_NAMES and "builtin" not in sig:
            sig.insert(0, "builtin")
        for s in sig:
            if s not in out:
                out.append(s)
    return out


def is_admin_equivalent(principal, access):
    return bool(principal_signals(principal, admin_roles(access)))


def describe_extra(principals, access):
    """Short text on what extra (non built-in) signals pulled principals in, for evidence strings."""
    by_name = admin_roles(access)
    if not by_name:
        return ""
    extra = {}
    for p in principals:
        sig = principal_signals(p, by_name)
        if sig and "builtin" not in sig:
            for s in sig:
                extra[s] = extra.get(s, 0) + 1
    if not extra:
        return ""
    parts = [f"{n} via {SIGNAL_LABELS[s]}" for s, n in sorted(extra.items(), key=lambda kv: -kv[1])]
    return "Beyond the built-in roles: " + "; ".join(parts) + "."
