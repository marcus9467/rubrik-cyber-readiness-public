"""High-level remediation steps and documentation links, keyed by finding id.

Every URL here came back from a docs.rubrik.com search and was then fetched (HTTP 200, TLS verified) on
2026-10-09; five search results were already 404 and were dropped. Rubrik reorganizes its docs, so re-run
tests/test_links.py before each customer delivery. Findings with no confirmed page deliberately have no link rather than a guessed one.
Console paths are quoted only where a docs page stated them (Settings > Security > ...).
Steps are intentionally short: what to do, not a procedure. The docs hold the procedure.
"""

D = "https://docs.rubrik.com/en-us/saas"

MFA_PASSKEYS = ("Passkeys for MFA (additional factor)", f"{D}/saas/passkeys_mfa.html")
MFA_TOTP_DEVICE = ("Changing the TOTP device", f"{D}/saas/mfa_changing_dev.html")
ROLE_PRIV = ("Setting data management privileges by Rubrik cluster", f"{D}/saas/common/setting_data_management_privileges.html")
ROLE_WIZARD = ("Creating an RBAC role (M365 Backup Storage example of the role wizard)", f"{D}/m365_backup_storage/m365_b_s_creating_rbac_role.html")
QAUTH_MT = ("Quorum authorization and multitenancy", f"{D}/qauth/qauth_and_mt.html")
QAUTH_RUN = ("Running an action after obtaining quorum authorization", f"{D}/qauth/running_qauth_action.html")
RL_OVERVIEW = ("Retention-locked SLA Domains", f"{D}/saas/retention_locked_sla_domain.html")
RL_MODES = ("Governance vs compliance retention lock", f"{D}/saas/behavioral_diff_gov_and_comp_rl_sla_domain.html")
VM_PROTECT = ("vSphere virtual machine protection", f"{D}/saas/vs_virtual_machine_protection.html")

REMEDIATION = {
    "ID-1": {
        "steps": [
            "Ask each listed user to enroll an authenticator app in their user preferences.",
            "When enrollment is complete, enforce MFA for the account (see MFA-1).",
        ],
        "docs": [MFA_TOTP_DEVICE],
    },
    "ID-2": {
        "steps": [
            "Review the inactive local accounts with their owners.",
            "Remove or lock the ones no longer needed, and move people to SSO where possible.",
        ],
        "docs": [("Account locking", f"{D}/saas/common/account_locking.html")],
    },
    "ID-3": {
        "steps": [
            "Keep two break-glass account owners.",
            "Give everyone else a scoped role instead.",
        ],
        "docs": [],
    },
    "ID-4": {
        "steps": [
            "Identify the integration behind each unused account and delete the ones nobody owns.",
            "Rotate the client secret on the rest and keep it in a secrets vault.",
        ],
        "docs": [],
    },
    "MFA-1": {
        "steps": [
            "Confirm every local user has enrolled (see ID-1).",
            "Turn on MFA enforcement in the account security settings.",
            "If the setting shows as locked, confirm with Rubrik what controls it.",
        ],
        "docs": [MFA_PASSKEYS],
    },
    "MFA-2": {
        "steps": ["Shorten the MFA remember period in the account's MFA settings."],
        "docs": [],
    },
    "Q-1": {
        "steps": [
            "Enable quorum authorization in the global organization; it also applies to tenant organizations.",
            "Create policies for destructive actions and give a small group the quorum approver role.",
        ],
        "docs": [QAUTH_MT, QAUTH_RUN],
    },
    "Q-2": {
        "steps": [
            "Raise the required approvals on each policy to 2 or more.",
            "Keep enough approvers that one absence cannot block a recovery.",
        ],
        "docs": [QAUTH_MT, QAUTH_RUN],
    },
    "R-1": {
        "steps": [
            "Design a few scoped roles, for example by workload type or by team.",
            "Move day-to-day users off Administrator. For SSO users, map identity provider groups to those roles.",
        ],
        "docs": [ROLE_PRIV, ROLE_WIZARD],
    },
    "R-2": {
        "steps": [
            "Create a role limited to what each integration actually calls.",
            "Reassign the service account to it and rotate its secret.",
        ],
        "docs": [ROLE_PRIV],
    },
    "R-3": {
        "steps": [
            "Enroll these admin accounts in TOTP first.",
            "Then enforce MFA for the account (see MFA-1).",
        ],
        "docs": [MFA_TOTP_DEVICE],
    },
    "R-4": {
        "steps": [
            "Open each flagged custom role and list which of its permissions touch users, roles, quorum, "
            "SLA retention or snapshot deletion.",
            "Remove those permissions from day-to-day roles, or split them into a separate role held by a "
            "few named people.",
        ],
        "docs": [],
    },
    "R-5": {
        "steps": [
            "In the IdP, list the members of each group mapped to an admin-equivalent role.",
            "Remap the group to a scoped role, or shrink it to the few people who need admin and name an owner.",
            "Add a recurring review of those groups' membership.",
        ],
        "docs": [],
    },
    "A-1": {
        "steps": [
            "List the admin office, VPN and automation egress ranges that need access.",
            "Add them to the allowlist before enabling it, including your own, so you do not lock yourself out.",
        ],
        "docs": [],
    },
    "A-2": {
        "steps": ["Enable brute-force lockout and set the attempt limit and auto-unlock time."],
        "docs": [
            ("Configuring account lockout settings", f"{D}/saas/common/configuring_account_lockout_settings.html"),
            ("Brute force lock", f"{D}/saas/common/brute_force_lock.html"),
        ],
    },
    "A-3": {
        "steps": [
            "Pick the identity provider (Okta, Entra ID or another SAML 2.0 provider).",
            "Exchange SAML metadata files between the identity provider and RSC, then run the SSO test.",
            "Authorize identity provider groups and map them to roles.",
        ],
        "docs": [
            ("SAML attributes required for RSC SSO", f"{D}/saas/saml_attr_sso_config.html"),
            ("Okta integration workflow", f"{D}/saas/okta_integration_workflow.html"),
            ("Configuring Azure SSO", f"{D}/saas/sso_azure_configuring_sso_in_rsc.html"),
        ],
    },
    "A-4": {
        "steps": ["Set the minimum length to 12 or more under Settings, Security, Password Policy."],
        "docs": [("Configuring password policy for local users", f"{D}/saas/configuring_password_policy_local_users.html")],
    },
    "S-1": {
        "steps": [
            "Pick the workloads that must survive an attacker with admin rights, such as critical databases.",
            "Create a retention-locked SLA Domain for them, after comparing governance and compliance modes.",
            "Rubrik's docs say retention lock needs CDM 7.0.2 or later and may need Rubrik Support to enable it on a cluster.",
        ],
        "docs": [RL_OVERVIEW, RL_MODES],
    },
    "S-2": {
        "steps": ["Where retention-locked SLAs archive data, enable compliance immutability on the archival location."],
        "docs": [("Archival policy", f"{D}/saas/archival_policy.html")],
    },
    "RP-1": {
        "steps": [
            "List the SLA Domains behind the affected objects and rank them by criticality.",
            "Add a replication target on another cluster to each SLA that protects critical workloads.",
            "Confirm the target cluster sits in a separate failure domain from the source.",
        ],
        "docs": [],
    },
    "RP-2": {
        "steps": [
            "List the SLA Domains behind the affected objects and rank them by criticality.",
            "Add an archival location (cloud or object storage) to each SLA that protects critical workloads.",
            "Where the SLA is retention locked, enable compliance immutability on that location.",
        ],
        "docs": [],
    },
    "RP-3": {
        "steps": [
            "Start with the SLAs holding the most objects and the most critical workloads.",
            "Add a replica on another cluster first, then an archive copy, so no SLA keeps a single copy.",
        ],
        "docs": [],
    },
    "C-1": {
        "steps": [
            "Sort the unprotected objects into: should be protected, intentionally excluded, and retired.",
            "Assign an SLA to the first group. Mark the second Do Not Protect with a named owner.",
        ],
        "docs": [VM_PROTECT, ("SLA Domain administration", f"{D}/saas/sla_domain_administration.html")],
    },
    "C-2": {
        "steps": [
            "Confirm with the owners which of the listed VMs really are non-production.",
            "Decide on a policy: a lighter SLA for non-production, or an explicit Do Not Protect.",
            "Mark environment with vCenter folders or tags so new VMs are picked up automatically.",
        ],
        "docs": [VM_PROTECT],
    },
    "C-3": {
        "steps": [
            "Decide which Rubrik cluster should protect each vCenter; the same vCenter can be added to more than one.",
            "Assign the SLA consistently, ideally at folder or vCenter level.",
        ],
        "docs": [VM_PROTECT],
    },
    "C-4": {
        "steps": [
            "Confirm the list with the customer: which systems must be up before anything else can be restored.",
            "Assign an SLA Domain to each, with retention lock, and add them to a recovery plan.",
        ],
        "docs": [],
    },
    "C-5": {
        "steps": [
            "In RSC, open the SLA compliance report, filter to Out of Compliance and sort by missed snapshots.",
            "Check each cause in turn: failed jobs, an SLA frequency the cluster cannot meet, a blackout window, "
            "or a disconnected host or cluster.",
            "Re-run the assessment after fixing; the figure covers the past 7 days.",
        ],
        "docs": [],
    },
    "CL-1": {
        "steps": ["Confirm with Rubrik Support whether this cluster can be encrypted at rest, or plan its replacement."],
        "docs": [],
    },
    "CL-2": {
        "steps": ["In RSC, open the Support Tunnel page, find each cluster with an open tunnel and close it."],
        "docs": [("Closing a support tunnel", f"{D}/saas/common/closing_a_support_tunnel.html")],
    },
    "CL-3": {
        "steps": ["Check the two-person rule setting on each cluster directly."],
        "docs": [("TPR requests (CDM)", "https://docs.rubrik.com/en-us/9.0/ug/cdm/tpr_requests.html")],
    },
    "T-1": {
        "steps": [
            "Confirm Threat Monitoring is covered by the current license before planning the rollout.",
            "Enable it on the listed clusters, accounts and subscriptions.",
        ],
        "docs": [("Threat Monitoring", f"{D}/saas/threat_monitoring.html")],
    },
    "T-10": {
        "steps": [
            "Check why the cluster is not reporting. A disconnected cluster returns no settings to RSC.",
            "Once it reconnects, open its threat monitoring settings in RSC and confirm they are on.",
        ],
        "docs": [],
    },
    "T-11": {
        "steps": [
            "Open the threat monitoring settings for each cluster that has it on.",
            "Turn on extended file scan coverage, or full scan, where the extra scan time is acceptable.",
        ],
        "docs": [],
    },
    "T-2": {
        "steps": [
            "Open the sensitive data results for the flagged objects in RSC.",
            "Fix the over-broad permissions in the source system, then re-scan.",
        ],
        "docs": [],
    },
    # Steps below have no doc links on purpose: none has been fetched and verified yet.
    "T-3": {
        "steps": [
            "Turn on anomaly alerting in the RSC anomaly detection settings.",
            "Send the alert to the on-call channel, not only to an inbox.",
        ],
        "docs": [],
    },
    "T-4": {
        "steps": [
            "Create a webhook for events and audit logs that points at the SIEM or paging tool.",
            "Send a test event and confirm it arrives.",
        ],
        "docs": [],
    },
    "T-5": {
        "steps": [
            "Open each failing webhook and read its last error.",
            "Fix the endpoint, credential or certificate, then send a test event.",
        ],
        "docs": [],
    },
    "T-6": {
        "steps": [
            "Decide who must hear about RSC events: the responders, the security team and the incident commander.",
            "Set up email notifications for those people. The default is to send none.",
            "Allow noreply@rubrik.com through the mail filter, then send a test.",
        ],
        "docs": [],
    },
    "T-7": {
        "steps": [
            "Open each event webhook and look at its message template.",
            "Switch to a template that includes eventInfo, then preview the payload to confirm it.",
            "Check the SIEM parses the new field.",
        ],
        "docs": [],
    },
    "T-8": {
        "steps": [
            "Decide which team investigates Warning events and whether they should reach it.",
            "Add Warning severity to a webhook that feeds that team, or create a second webhook for it.",
        ],
        "docs": [],
    },
    "T-9": {
        "steps": [
            "Add a syslog export rule on each affected cluster, pointing at the SIEM.",
            "Or add an SNMP trap receiver if the monitoring team works from traps.",
            "Send a test event and confirm it arrives.",
        ],
        "docs": [],
    },
    "RC-1": {
        "steps": [
            "Start with the identity tier (domain controllers, Entra Connect) and the top business applications.",
            "Record the restore order and the people who run each step.",
        ],
        "docs": [],
    },
    "RC-2": {
        "steps": [
            "Run each listed plan as a test recovery into an isolated network.",
            "Record the recovery time, fix what failed, and schedule a recurring test.",
        ],
        "docs": [],
    },
    "RC-3": {
        "steps": [
            "Open the failed recovery and read the failing step.",
            "Fix the cause and rerun the plan until it succeeds.",
        ],
        "docs": [],
    },
    # Visibility gaps. Steps only: no doc links have been fetched and verified for these.
    "V-1": {
        "steps": [
            "Turn it on for every cluster and cloud account, then point alerts at the on-call channel.",
        ],
        "docs": [],
    },
    "V-2": {
        "steps": [
            "Enrol every cluster, cloud account and SaaS tenant so every backup is scanned on arrival.",
        ],
        "docs": [],
    },
    "V-4": {
        "steps": [
            "Turn it on for the systems that hold regulated data first, then widen it.",
            "Fix the open-access findings it reports (see T-2).",
        ],
        "docs": [],
    },
}
