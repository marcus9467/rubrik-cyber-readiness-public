"""Turn a collected bundle into findings and per-domain scores.

Rules live here as plain functions (no YAML dependency). Each returns a finding dict or None.
`tag` says where the fix lives:
  fix_now      configurable today
  visibility   a detection capability the tenant cannot see (scored 0 to 100 in capabilities.py)
  process      people / runbook gap
Thresholds marked GUIDANCE are judgment calls, not Rubrik-published limits.
"""
import json
from datetime import datetime, timedelta, timezone

import capabilities
from editions import bucket, edition_of
from frameworks import framework_of
import rbac
import tier0
from remediation import REMEDIATION

SEVERITY_PENALTY = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
STALE_DAYS = 90  # GUIDANCE
REMEMBER_HOURS_MAX = 24  # GUIDANCE


def _f(rule_id, domain, severity, title, evidence, remediation, tag):
    extra = REMEDIATION.get(rule_id, {})
    return {
        "id": rule_id, "domain": domain, "severity": severity, "title": title,
        "evidence": evidence, "remediation": remediation, "tag": tag,
        "steps": list(extra.get("steps", [])), "docs": [list(d) for d in extra.get("docs", [])],
        "edition": edition_of(rule_id), "bucket": bucket(tag, rule_id),
        "framework": framework_of(rule_id),
    }


def _ok(section):
    """True if a collected section is usable (present and not an error stub)."""
    return isinstance(section, (dict, list)) and not (isinstance(section, dict) and "error" in section)


def _days_since(iso):
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


# ---- Identity -------------------------------------------------------------------------------

def id_totp_missing(d):
    users = d.get("identity", {}).get("users")
    if not users:
        return None
    local = [u for u in users if u["totpStatus"]["isSupported"]]
    missing = [u for u in local if not u["totpStatus"]["isEnabled"]]
    if not missing:
        return None
    cockpit = ""
    for m in (d.get("dhrc", {}).get("scores", {}).get("SECURITY_CONFIG", {}) or {}).get("metrics", []):
        # Only a citation: a null or missing value must never stop the finding itself from firing.
        if m.get("metric") == "USERS_USING_TOTP" and m.get("value") is not None and m.get("maxValue") is not None:
            cockpit = (f" The RSC cockpit reports {m['value']:.0f} of {m['maxValue']:.0f} users using TOTP; "
                       "it can differ slightly from this user-list count (population not reproducible via API).")
    return _f("ID-1", "Identity", "high", "Local users without TOTP configured",
              f"{len(missing)} of {len(local)} local users have no TOTP configured "
              f"({len(users) - len(local)} SSO users are not applicable; RSC marks them NA_SSO)." + cockpit,
              "Have each user enroll TOTP, then enforce it globally (see MFA-1).", "fix_now")


def id_stale_users(d):
    users = d.get("identity", {}).get("users")
    if not users:
        return None
    local = [u for u in users if u["domain"] == "LOCAL"]
    stale = [u for u in local if (_days_since(u["lastLogin"]) is None or _days_since(u["lastLogin"]) > STALE_DAYS)]
    if not stale:
        return None
    return _f("ID-2", "Identity", "medium", f"Local users inactive for {STALE_DAYS}+ days",
              f"{len(stale)} of {len(local)} local users have not logged in for {STALE_DAYS} days or ever.",
              "Disable or remove unused local accounts; prefer SSO for people.", "fix_now")


def id_account_owners(d):
    users = d.get("identity", {}).get("users")
    if not users:
        return None
    owners = sum(u["isAccountOwner"] for u in users)
    if owners <= 2:
        return None
    return _f("ID-3", "Identity", "medium", "Many account owners",
              f"{owners} users hold account owner (guidance: 2 or fewer).",
              "Reduce to the minimum (typically 2 break-glass owners) and use scoped roles for everyone else.",
              "fix_now")


def id_service_accounts(d):
    sa = d.get("access", {}).get("serviceAccounts")
    if not _ok(sa) or not sa:
        return None
    stale = [s for s in sa if (_days_since(s["lastLogin"]) is None or _days_since(s["lastLogin"]) > STALE_DAYS)]
    if not stale:
        return None
    return _f("ID-4", "Identity", "medium", "Unused service accounts",
              f"{len(stale)} of {len(sa)} service accounts have not authenticated in {STALE_DAYS} days or ever.",
              "Delete service accounts no longer in use and rotate secrets on the rest.", "fix_now")


# ---- MFA ------------------------------------------------------------------------------------

def mfa_not_enforced(d):
    m = d.get("mfa")
    if not _ok(m) or m.get("isTotpEnforcedGlobal"):
        return None
    return _f("MFA-1", "MFA", "high", "TOTP not enforced globally",
              "Global TOTP enforcement is off"
              + (" and the setting is locked" if m.get("isTotpGlobalEnforceLocked") else "")
              + (", although TOTP is marked mandatory." if m.get("isTotpMandatory") else "."),
              "Enforce TOTP for all local users once enrollment is complete.", "fix_now")


def mfa_remember(d):
    m = d.get("mfa")
    if not _ok(m) or m.get("mfaRememberHours", 0) <= REMEMBER_HOURS_MAX:
        return None
    return _f("MFA-2", "MFA", "low", "Long MFA remember window",
              f"MFA is remembered for {m['mfaRememberHours']} hours (guidance: {REMEMBER_HOURS_MAX} or less).",
              "Shorten the remember window.", "fix_now")


# ---- Quorum ---------------------------------------------------------------------------------

def q_disabled(d):
    cfg = d.get("quorum", {}).get("config")
    if not cfg:
        return None
    off = [o for o, c in cfg.items() if not c["isTprEnabled"]]
    if not off:
        return None
    return _f("Q-1", "Quorum", "critical", "Quorum authorization disabled",
              f"TPR is disabled in {len(off)} of {len(cfg)} organizations.",
              "Enable quorum authorization and define policies for destructive actions.", "fix_now")


def q_single_approver(d):
    q = d.get("quorum")
    if not q or not q.get("config"):
        return None
    weak = [p for p in q["policies"] if p["quorumRequirement"] < 2]
    static = [c["staticQuorumRequirement"] for c in q["config"].values() if c["isTprEnabled"]]
    if not weak and not any(s < 2 for s in static):
        return None
    return _f("Q-2", "Quorum", "high", "Quorum requires only one approver",
              f"{len(weak)} of {len(q['policies'])} policies need a single approval; static quorum is "
              f"{min(static) if static else 'n/a'}.",
              "Raise the approval requirement to 2 or more (GUIDANCE) so no single approver can authorize "
              "a destructive action. Confirm how RSC treats the requester's own approval.", "fix_now")


# ---- Access ---------------------------------------------------------------------------------

def a_allowlist(d):
    ip = d.get("access", {}).get("ipAllowlist")
    if not _ok(ip) or ip.get("enabled"):
        return None
    return _f("A-1", "Access", "high", "IP allowlist disabled",
              "Any IP address can reach the RSC login.", "Enable the IP allowlist for admin networks and VPN egress.",
              "fix_now")


def a_lockout(d):
    lo = d.get("access", {}).get("lockout")
    if not _ok(lo) or lo.get("isBruteForceLockoutEnabled"):
        return None
    return _f("A-2", "Access", "high", "Brute-force lockout disabled",
              "Accounts are not locked after repeated failed logins.", "Enable lockout.", "fix_now")


def a_no_sso(d):
    # hasIdp is a boolean. Only an explicit False means "no provider"; an error stub or a missing key is unknown.
    has = d.get("access", {}).get("hasIdp")
    if has is not False:
        return None
    return _f("A-3", "Access", "high", "No SSO identity provider configured",
              "All users authenticate with local passwords.",
              "Integrate the corporate IdP so MFA and offboarding are centrally controlled.", "fix_now")


def a_password(d):
    pw = d.get("access", {}).get("passwordPolicy")
    if not _ok(pw):
        return None
    length = pw["lengthPolicy"]
    if length["isActive"] and length["defaultValue"] >= 12:
        return None
    return _f("A-4", "Access", "medium", "Weak minimum password length",
              f"Length policy: {'default ' + str(length['defaultValue']) if length['isActive'] else 'not active'}.",
              "Require 12+ characters.", "fix_now")


# ---- RBAC -----------------------------------------------------------------------------------
# Admin-equivalence is decided in rbac.py from each role's effective permissions (author's judgment);
# the built-in names Administrator/Owner stay as a floor. `isReadOnly` on a role means "built-in, not
# editable", not "grants read-only access". If permissions were not collected, name-only matching applies.
ADMIN_ROLES = rbac.BUILTIN_ADMIN_NAMES
ADMIN_SHARE_HIGH = 0.5    # GUIDANCE
ADMIN_SHARE_MEDIUM = 0.25  # GUIDANCE


def _is_admin(principal, access=None):
    """Admin-equivalent by effective permissions (rbac.py), with the built-in name match as a floor."""
    return rbac.is_admin_equivalent(principal, access)


def _basis(access):
    """Evidence fragment saying what the count rests on."""
    return ("Admin-equivalent = Administrator/Owner or a role with identity, quorum, backup-destroy or "
            "broad rights." if rbac.admin_roles(access) else "Roles are matched by name only "
            "(role permissions were not readable).")


def r_admin_share(d):
    users = d.get("identity", {}).get("users")
    if not users:
        return None
    acc = d.get("access", {})
    admins = [u for u in users if _is_admin(u, acc)]
    share = len(admins) / len(users)
    if share <= ADMIN_SHARE_MEDIUM:
        return None
    sso = sum(u["domain"] != "LOCAL" for u in admins)
    return _f("R-1", "RBAC", "high" if share > ADMIN_SHARE_HIGH else "medium",
              "Most users hold a full-admin role",
              f"{len(admins)} of {len(users)} users ({share:.0%}) hold an admin-equivalent role "
              f"({len(admins) - sso} local, {sso} SSO). {rbac.describe_extra(admins, acc)} {_basis(acc)}".replace("  ", " "),
              "Create scoped roles (for example per workload type or per team) and move day-to-day users "
              "off Administrator. For SSO, map IdP groups to scoped roles.", "fix_now")


def r_admin_service_accounts(d):
    acc = d.get("access", {})
    sa = acc.get("serviceAccounts")
    if not _ok(sa) or not sa or "roles" not in sa[0]:
        return None
    admins = [s for s in sa if _is_admin(s, acc)]
    if not admins:
        return None
    share = len(admins) / len(sa)
    return _f("R-2", "RBAC", "high" if share > ADMIN_SHARE_HIGH else "medium",
              "Service accounts with full-admin rights",
              f"{len(admins)} of {len(sa)} service accounts ({share:.0%}) hold an admin-equivalent role. "
              f"{rbac.describe_extra(admins, acc)} A leaked client secret for any of them would carry "
              f"administrator-level access.".replace("  ", " "),
              "Give each integration a role limited to what it calls, and rotate secrets on the rest.",
              "fix_now")


def r_admin_without_totp(d):
    users = d.get("identity", {}).get("users")
    if not users:
        return None
    acc = d.get("access", {})
    risky = [u for u in users if _is_admin(u, acc) and u["totpStatus"]["isSupported"]
             and not u["totpStatus"]["isEnabled"]]
    if not risky:
        return None
    return _f("R-3", "RBAC", "high", "Local admins without TOTP",
              f"{len(risky)} local users with an admin-equivalent role have no TOTP configured. "
              f"{rbac.describe_extra(risky, acc)}".strip(),
              "Enroll these accounts in TOTP first; they carry the most risk if a password leaks.", "fix_now")


def r_custom_admin_roles(d):
    """R-4: custom (non built-in) roles whose permissions make them admin-equivalent."""
    acc = d.get("access", {})
    roles = rbac.usable_roles(acc)
    if not roles:
        return None
    custom = [r for r in roles if r["name"] not in rbac.BUILTIN_ADMIN_NAMES and not r.get("isReadOnly")
              and not r.get("isOrgAdmin") and rbac.role_signals(r)]
    if not custom:
        return None
    users = d.get("identity", {}).get("users") or []
    names = {r["name"] for r in custom}
    holders = sum(any(x["name"] in names for x in u.get("roles", [])) for u in users)
    return _f("R-4", "RBAC", "medium", "Custom roles with admin-equivalent rights",
              f"{len(custom)} of {len([r for r in roles if not r.get('isReadOnly')])} custom roles can "
              f"manage users or roles, change quorum, remove backups, or hold a very broad permission set "
              f"(held by {holders} users). A role name does not show this.",
              "Review each flagged role's permissions and remove what the team does not need.", "fix_now")


def r_sso_admin_groups(d):
    """R-5: SSO groups mapped to admin-equivalent roles, and local users who also hold admin."""
    acc = d.get("access", {})
    groups = acc.get("ssoGroups")
    if not _ok(groups) or not groups:
        return None
    by_name = rbac.admin_roles(acc)
    admin_groups = [g for g in groups if rbac.principal_signals(g, by_name)]
    if not admin_groups:
        return None
    covered = sum(g.get("userCount", 0) for g in admin_groups)
    users = d.get("identity", {}).get("users") or []
    local_admins = sum(u["domain"] == "LOCAL" and _is_admin(u, acc) for u in users)
    return _f("R-5", "RBAC", "medium", "SSO groups mapped to admin roles",
              f"{len(admin_groups)} of {len(groups)} SSO groups map to an admin-equivalent role, covering "
              f"{covered} users who have signed in; {local_admins} local users also hold admin. Anyone "
              f"added to these groups in the IdP becomes an RSC admin.",
              "Map groups to scoped roles, keep admin groups small with named owners, and review "
              "membership on a schedule.", "fix_now")


# ---- Immutability / SLAs --------------------------------------------------------------------

def s_retention_lock(d):
    s = d.get("sla")
    if not s or not s["inUse"]:
        return None
    if s["inUseLocked"] == s["inUse"]:
        return None
    sev = "high" if s["inUseLocked"] == 0 else "medium"
    return _f("S-1", "Immutability", sev, "Few SLAs use retention lock",
              f"{s['inUseLocked']} of {s['inUse']} SLAs with protected objects are retention locked "
              f"({s['retentionLocked']} of {s['total']} overall); only {s['objectsOnLockedSlas']} objects "
              f"sit on a locked SLA out of {s['objectsOnAnySla']} on any SLA.",
              "Apply a retention-locked SLA to critical workloads so snapshots cannot be shortened or deleted early.",
              "fix_now")


def s_immutable_archive(d):
    s = d.get("sla")
    if not s or not s["withArchival"] or s["withImmutableArchival"]:
        return None
    return _f("S-2", "Immutability", "medium", "No archival specs use compliance immutability",
              f"{s['withArchival']} SLAs archive data, none with compliance immutability enabled.",
              "Enable compliance immutability on archival locations for locked SLAs.", "fix_now")


# ---- Coverage -------------------------------------------------------------------------------

def c_unprotected(d):
    u = d.get("inventory", {}).get("unprotected")
    if not u or not u["total"]:
        return None
    return _f("C-1", "Coverage", "high", "Active objects with no protection",
              f"{u['noSla']} active objects have no SLA and {u['doNotProtect']} are set to Do Not Protect "
              f"(object records, not distinct workloads; {u['logicalBytes'] / 1e12:.0f} TB logical).",
              "Review each class; assign an SLA or document the exception.", "process")


def c_nonprod(d):
    v = d.get("inventory", {}).get("vmEnvironment")
    if not v or not v["nonProd"]["total"]:
        return None
    n = v["nonProd"]
    if not n["unprotected"]:
        return None
    return _f("C-2", "Coverage", "medium", "Likely test/dev VMs unprotected",
              f"{n['unprotected']} of {n['total']} VMs whose name suggests non-production have no SLA "
              f"(name-pattern heuristic; confirm with the customer).",
              "Protect or explicitly exclude non-production workloads; use vCenter folders or tags so "
              "environment is machine-readable.", "process")


def c_partial(d):
    v = d.get("inventory", {}).get("vmEnvironment")
    if not v or not v["partiallyProtected"]:
        return None
    return _f("C-3", "Coverage", "medium", "VMs protected from some clusters only",
              f"{v['partiallyProtected']} of {v['activeVms']} VMs are protected via some clusters but not others.",
              "Assign the SLA at the vCenter or folder level so every cluster inherits it.", "fix_now")


BACKUP_HEALTH_HIGH = 0.10  # GUIDANCE: share of assessed objects out of compliance that moves this to high


def c_backup_health(d):
    b = d.get("inventory", {}).get("backupHealth")
    if not b or not b["outOfCompliance"]:
        return None
    assessed = b["inCompliance"] + b["outOfCompliance"]
    share = b["outOfCompliance"] / assessed
    unknown = b["notAvailable"] + b["empty"]
    ev = (f"{b['outOfCompliance']} of {assessed} protected active objects missed snapshots against their SLA "
          f"in the past 7 days (object records, not distinct workloads).")
    if unknown:
        ev += f" A further {unknown} could not be assessed by RSC and are not counted."
    return _f("C-5", "Coverage", "high" if share >= BACKUP_HEALTH_HIGH else "medium",
              "Protected objects are missing snapshots", ev,
              "Find why each object is out of compliance before the next incident; a protected object that "
              "is not backing up is not recoverable.", "fix_now")


# ---- Platform / threat ----------------------------------------------------------------------

def c_tier0(d):
    rows = d.get("inventory", {}).get("unprotected", {}).get("rows")
    if not rows:
        return None
    found = tier0.find(rows)
    if not found:
        return None
    structural = [e for e in found if e["confidence"] == "structural"]
    kinds = sorted({e["kind"] for e in found})
    ev = (f"{len(found)} likely Tier-0 assets have no protection ({len(structural)} by RSC object type, "
          f"{len(found) - len(structural)} by name only), such as {', '.join(e['name'] for e in found[:2])}.")
    return _f("C-4", "Coverage", "critical" if structural else "high",
              "Likely Tier-0 assets unprotected", ev,
              "Protect identity, vCenter and core network services first, with retention lock.", "fix_now")


def cl_encryption(d):
    c = d.get("clusters")
    if not c or not c["encryptionOff"]:
        return None
    return _f("CL-1", "Platform", "high", "Cluster without encryption at rest",
              f"{c['encryptionOff']} of {c['total']} clusters report encryption disabled.",
              "Use an encryption-capable cluster or replace it.", "process")


def cl_tunnel(d):
    c = d.get("clusters")
    if not c or not c["supportTunnelOpen"]:
        return None
    return _f("CL-2", "Platform", "medium", "Support tunnels left open",
              f"{c['supportTunnelOpen']} of {c['total']} clusters have an open support tunnel.",
              "Close tunnels when no support case is active.", "fix_now")


def cl_tpr_unknown(d):
    c = d.get("clusters")
    if not c or not c["tprUnknown"]:
        return None
    return _f("CL-3", "Platform", "info", "Cluster-level quorum status not reported",
              f"RSC did not report quorum state for {c['tprUnknown']} of {c['total']} clusters.",
              "Confirm cluster-level quorum settings directly on each cluster.", "process")


def t_threat_monitoring(d):
    roots = d.get("threat", {}).get("roots")
    if not roots:
        return None
    gaps = []
    for name, r in roots.items():
        if "error" in r or r["total"] == 0:
            continue
        if r["threatMonitoringEnabled"] < r["total"]:
            label = "Rubrik clusters" if name == "CDM_CLUSTER" else name
            gaps.append(f"{label}: {r['threatMonitoringEnabled']} of {r['total']}")
    if not gaps:
        return None
    return _f("T-1", "Threat Monitoring", "medium", "Threat monitoring not enabled everywhere",
              "Enabled roots: " + "; ".join(gaps) + ".",
              "Enable threat monitoring on the remaining clusters, accounts and subscriptions.", "visibility")


def t_cdm_not_assessed(d):
    r = d.get("threat", {}).get("roots", {}).get("CDM_CLUSTER")
    if not isinstance(r, dict) or "error" in r or not r.get("notAssessed"):
        return None
    na = r["notAssessed"]
    # Counts only: evidence text must read the same before and after redaction. Names are in the bundle.
    return _f("T-10", "Threat Monitoring", "info", "Cluster threat monitoring status not reported",
              f"RSC returned no threat monitoring settings for {len(na)} of {len(na) + r['total']} clusters, "
              "usually because they are disconnected.",
              "Reconnect the cluster, then confirm threat monitoring is enabled.", "process")


def t_cdm_smart_scan(d):
    r = d.get("threat", {}).get("roots", {}).get("CDM_CLUSTER")
    if not isinstance(r, dict) or "error" in r or not r.get("threatMonitoringEnabled"):
        return None
    on = [i for i in r["items"] if i["threatMonitoringEnabled"]]
    off = [i for i in on if not i["smartScanningEnabled"] and not i["fullScanEnabled"]]
    if not off:
        return None
    return _f("T-11", "Threat Monitoring", "low", "Cluster threat monitoring runs at default scan depth",
              f"{len(off)} of {len(on)} clusters with threat monitoring have neither extended file scan coverage "
              "nor full scan on, so only the default file extensions are scanned.",
              "Turn on extended file scan coverage where scan time allows.", "visibility")


def t_open_sensitive(d):
    sc = d.get("dhrc", {}).get("scores", {}).get("SENSITIVE_DATA")
    if not sc:
        return None
    m = next((x for x in sc["metrics"] if x["metric"] == "OPEN_ACCESS_SENSITIVE_FILES"), None)
    if not m or not m["value"]:
        return None
    return _f("T-2", "Sensitive Data Discovery", "high", "Sensitive files with open access",
              f"RSC reports {int(m['value'])} of {int(m['maxValue'])} sensitive files with open access.",
              "Review and tighten permissions on the flagged files.", "process")


def t_anomaly_alerts(d):
    s = d.get("detection", {}).get("settings")
    if not _ok(s) or s.get("isAnomalyAlertEnabled") is not False:
        return None
    return _f("T-3", "Alerting", "high", "Anomaly alerts are turned off",
              "RSC is not set to alert when a workload snapshot looks anomalous, so detections wait for someone to open the console.",
              "Turn on anomaly alerting and route it to the people who respond.", "fix_now")


def t_event_forwarding(d):
    w = d.get("detection", {}).get("webhooks")
    if not _ok(w):
        return None
    if w["enabled"] == 0:
        return _f("T-4", "Alerting", "medium", "No event or audit forwarding configured",
                  "No enabled webhook sends RSC events or audit logs to a SIEM or ticketing system "
                  "(syslog export on CDM clusters is not assessed).",
                  "Forward RSC events and audit logs to the team's SIEM or paging tool.", "fix_now")
    if w["withAuditFeed"] == 0 and w["withEventFeed"] == 0:
        return _f("T-4", "Alerting", "medium", "Webhooks carry neither events nor audit logs",
                  f"{w['enabled']} webhook(s) are enabled but none subscribes to events or audits.",
                  "Subscribe at least one webhook to events and audit logs.", "fix_now")
    return None


def t_webhooks_failing(d):
    w = d.get("detection", {}).get("webhooks")
    if not _ok(w) or not w.get("failing"):
        return None
    return _f("T-5", "Alerting", "medium", "Webhook deliveries are failing",
              f"{w['failing']} of {w['enabled']} enabled webhooks reported a delivery error on their last failure.",
              "Check the endpoint, credentials and certificate for each failing webhook.", "fix_now")


def t_email_unused(d):
    e = d.get("detection", {}).get("email")
    if not _ok(e) or not e.get("users") or e.get("emailEnabled"):
        return None
    return _f("T-6", "Alerting", "medium", "No one receives RSC email notifications",
              f"None of {e['users']} users has email notifications on. RSC sends no email unless each user is set up, "
              "so anyone who relies on email, including the security team, hears nothing.",
              "Set up email for the people who respond, and route the critical alerts to security as well.", "process")


def t_template_missing_eventinfo(d):
    r = d.get("detection", {}).get("webhookRouting")
    if not _ok(r) or not r.get("withoutEventInfo"):
        return None
    return _f("T-7", "Alerting", "medium", "Event webhook payload omits threat detail",
              f"{r['withoutEventInfo']} of {r['templateChecked']} event webhooks use a template without eventInfo, so "
              "Threat Monitoring and threat hunting matches reach the SIEM without the detail the SOC needs.",
              "Switch the webhook to a template that includes eventInfo and preview the payload.", "fix_now")


def t_critical_only(d):
    r = d.get("detection", {}).get("webhookRouting")
    if not _ok(r) or not r.get("eventWebhooks") or r.get("criticalOnly") != r["eventWebhooks"]:
        return None
    return _f("T-8", "Alerting", "medium", "Every event webhook is limited to Critical severity",
              f"All {r['eventWebhooks']} event webhooks send only Critical events. Warning-level events, which include "
              "anomalies with low levels of detected encryption, never leave RSC.",
              "Add Warning to at least one webhook that feeds the team that investigates.", "process")


def t_cdm_silent(d):
    c = d.get("detection", {}).get("cdmNotifications")
    if not _ok(c) or not c.get("neither"):
        return None
    return _f("T-9", "Alerting", "medium", "CDM clusters send no syslog and no SNMP traps",
              f"{c['neither']} of {c['checked']} readable CDM clusters have no syslog export rule and no SNMP trap "
              "receiver, so events on those clusters reach no external system from the cluster itself.",
              "Configure a syslog export rule or an SNMP trap receiver on each cluster.", "process")


def rc_no_plans(d):
    r = d.get("recovery")
    if not _ok(r) or r["total"] > 0:
        return None
    return _f("RC-1", "Recovery", "high", "No recovery plans defined",
              "RSC has no recovery plans, so there is no rehearsed, documented order for restoring the business.",
              "Define recovery plans for the critical applications and the identity tier first.", "process")


def rc_never_run(d):
    r = d.get("recovery")
    if not _ok(r) or not r["total"] or not r["neverRun"]:
        return None
    share = r["neverRun"] / r["total"]
    sev = "high" if share >= 0.5 else "medium"
    return _f("RC-2", "Recovery", sev, "Recovery plans never tested",
              f"{r['neverRun']} of {r['total']} recovery plans have never completed a recovery or test.",
              "Run each plan as a test recovery, fix what breaks, then schedule a recurring test.", "process")


def rc_last_failed(d):
    r = d.get("recovery")
    if not _ok(r) or not r.get("lastRunFailed"):
        return None
    return _f("RC-3", "Recovery", "high", "Latest recovery test failed",
              f"{r['lastRunFailed']} of {r['total']} recovery plans ended their last recovery in FAILED.",
              "Open the failed recovery, fix the cause and rerun it.", "process")


OFFSITE_HIGH = 0.5    # GUIDANCE
OFFSITE_MEDIUM = 0.1  # GUIDANCE


def _offsite(d, rule_id, key, known_key, title, what, fix):
    o = d.get("offsite")
    # Unknown (error stub, or RSC returned no spec list) is never a gap: count only known objects.
    if not _ok(o) or not o.get(known_key) or not o.get(key):
        return None
    share = o[key] / o[known_key]
    sev = "high" if share >= OFFSITE_HIGH else "medium" if share >= OFFSITE_MEDIUM else "low"
    active = o.get("basis") == "active-protected"
    fell_back = o.get("fallbackSlas") or 0
    note = ""
    if not active:
        # Older bundle: the count is RSC's per-SLA record count, which includes relic and archived records.
        snap = d.get("inventory", {}).get("reconciliation", {}).get("snappables") or {}
        extra = (snap.get("relic") or 0) + (snap.get("archived") or 0)
        if extra and snap.get("activeProtected"):
            note = (f" This bundle counts every object record under an SLA, including relic and archived "
                    f"records: the tenant has {snap['activeProtected']:,} active protected objects and "
                    f"{extra:,} relic or archived records, so the share among active workloads may differ.")
    elif fell_back:
        note = (f" For {fell_back} SLAs the active count could not be read, so their record count (which includes "
                f"relic and archived records) was used instead.")
    what_objects = "active protected objects" if active and not fell_back else "object records"
    return _f(rule_id, "Recovery", sev, title,
              f"{o[key]} of {o[known_key]} {what_objects} ({share:.0%}) {what} "
              f"(object records, not distinct workloads).{note}",
              fix, "fix_now")


def rp_no_replica(d):
    return _offsite(d, "RP-1", "noReplication", "objectsReplicationKnown",
                    "Protected objects with no replica on another cluster",
                    "sit on SLAs with no replication target",
                    "Add a replication target to the SLA Domains that protect critical workloads.")


def rp_no_archive(d):
    return _offsite(d, "RP-2", "noArchival", "objectsArchivalKnown",
                    "Protected objects with no archive copy",
                    "sit on SLAs with no archival location",
                    "Add a cloud or object archival location to the SLA Domains that protect critical workloads.")


def rp_single_copy(d):
    return _offsite(d, "RP-3", "singleCopy", "objectsBothKnown",
                    "Protected objects with a single copy only",
                    "sit on SLAs with neither replication nor archival",
                    "Give these SLAs a second copy in another location, then an archive copy.")


def _visibility(d, domain, rule_id, remediation):
    c = capabilities.compute(d, d.get("_status"))[domain]
    if c["state"] in ("active", "not_collected"):
        return None
    dark = c["state"] in ("blind", "off")
    title = capabilities.GAP_TITLE[domain][0 if dark else 1]
    sev = "critical" if dark else "high" if (c["share"] or 0) < 0.5 else "medium"
    return _f(rule_id, domain, sev, title, f"{c['evidence']} {capabilities.consequence(domain, c['state'])}",
              remediation, "visibility")


def v_anomaly(d):
    return _visibility(d, "Anomaly Detection", "V-1", "Get anomaly detection running on every cluster and account.")


def v_monitoring(d):
    # When some accounts are simply not enrolled, T-1 already says which. Do not report the same gap twice.
    if t_threat_monitoring(d):
        return None
    return _visibility(d, "Threat Monitoring", "V-2", "Get threat monitoring running on every cluster and account.")


def v_sensitive(d):
    return _visibility(d, "Sensitive Data Discovery", "V-4", "Get sensitive data discovery running on regulated data.")


RULES = [
    id_totp_missing, id_stale_users, id_account_owners, id_service_accounts,
    mfa_not_enforced, mfa_remember, q_disabled, q_single_approver,
    a_allowlist, a_lockout, a_no_sso, a_password,
    r_admin_share, r_admin_service_accounts, r_admin_without_totp, r_custom_admin_roles, r_sso_admin_groups,
    s_retention_lock, s_immutable_archive, c_unprotected, c_nonprod, c_partial, c_tier0, c_backup_health,
    cl_encryption, cl_tunnel, cl_tpr_unknown, t_threat_monitoring, t_cdm_not_assessed, t_cdm_smart_scan,
    t_open_sensitive,
    t_anomaly_alerts, t_event_forwarding, t_webhooks_failing,
    t_email_unused, t_template_missing_eventinfo, t_critical_only, t_cdm_silent,
    rc_no_plans, rc_never_run, rc_last_failed,
    rp_no_replica, rp_no_archive, rp_single_copy,
    v_anomaly, v_monitoring, v_sensitive,
]


def score(bundle):
    data = dict(bundle["data"])
    data["_status"] = bundle["status"]  # the capability rules need to tell "collector failed" from "never ran"
    findings, skipped = [], []
    for rule in RULES:
        try:
            f = rule(data)
            if f:
                findings.append(f)
        except Exception as e:  # a rule must never sink the report
            skipped.append({"rule": rule.__name__, "error": str(e)[:200]})
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"]))

    domains = {}
    for f in findings:
        domains.setdefault(f["domain"], []).append(f)
    scores = {dom: max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in fs)) for dom, fs in domains.items()}
    # The three detection capabilities are scored by what the tenant can see, and a capability with no data is a 0,
    # not an unscored gap. Findings in the same area can only pull the score lower.
    caps = capabilities.compute(data, bundle["status"])
    for dom, c in caps.items():
        if c["score"] is not None:
            scores[dom] = min(c["score"], scores.get(dom, 100))
    # Domains with no findings score 100, but only if the collector behind them ran.
    return {
        "customer": bundle["customer"],
        "collected_at": bundle["collected_at"],
        "collector_status": bundle["status"],
        "findings": findings,
        "domain_scores": scores,
        "capabilities": caps,
        "hunt_note": capabilities.hunt_note(data, bundle["status"]),
        "counts": {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER},
        "skipped_rules": skipped,
        "rsc_scores": {k: v["value"] for k, v in data.get("dhrc", {}).get("scores", {}).items()},
    }


if __name__ == "__main__":
    import sys
    b = json.load(open(sys.argv[1]))
    r = score(b)
    for f in r["findings"]:
        print(f"{f['severity']:8} {f['id']:5} {f['title']}")
    print(r["counts"], r["skipped_rules"])
