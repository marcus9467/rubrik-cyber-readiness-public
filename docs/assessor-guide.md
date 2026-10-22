# Rubrik Cyber Readiness Assessment: Assessor Guide

For the Rubrik team. The customer-facing quick start is the [README](../README.md).

A read-only assessment of a Rubrik Security Cloud (RSC) tenant. It reads configuration and inventory through
a service account, scores what it finds, and produces a PDF: an executive summary on page 1, ranked findings
with evidence and fix steps, and a 30/60/90 day roadmap.

- **Read-only.** The toolkit issues GraphQL queries only. It contains no mutations and changes nothing in the tenant.
- **Safe to hand off.** The customer runs collection and sends back a redacted file. The report is built from that file.
- **Honest about gaps.** A query that is denied or fails is reported as "not assessed". It is never scored as clean.

## Contents

1. [Who does what](#who-does-what)
2. [What the assessment covers](#what-the-assessment-covers)
3. [Customer guide](#customer-guide)
4. [Assessor guide](#assessor-guide)
5. [Data handling and privacy](#data-handling-and-privacy)
6. [Reading the report](#reading-the-report)
7. [Alerting and notifications](#alerting-and-notifications)
8. [Re-running and tracking progress](#re-running-and-tracking-progress)
9. [Troubleshooting](#troubleshooting)
10. [Known limits](#known-limits)
11. [Development](#development)
12. [Repository layout](#repository-layout)

## Who does what

The work splits in two so the customer never needs a browser, fonts or the report tooling.

| Step | Who | Needs | Output |
|---|---|---|---|
| Create a service account | Customer RSC admin | RSC admin access | `service-account.json` |
| Preflight | Customer | PowerShell, or Python 3 and `requests` | Pass/fail per section |
| Collect and redact | Customer | PowerShell, or Python 3 and `requests` | `bundle.redacted.json` |
| Review and send | Customer security team | A text editor | `bundle.redacted.json` only |
| Render the PDF | Assessor | Python 3, Google Chrome or Chromium | `report.pdf` |

## What the assessment covers

Twelve collectors read the tenant. They feed 13 scored areas and three detection capabilities.

| Collector | Reads |
|---|---|
| `identity` | Users: email, domain, status, account-owner flag, last login, TOTP status, assigned roles |
| `mfa` | Global MFA/TOTP enforcement and remember-window settings |
| `quorum` | Quorum (TPR) configuration and custom policies |
| `inventory` | Protected vs supported objects per platform, unprotected active objects, Do Not Protect, VM-level detail |
| `sla` | SLA domains: retention lock, replication, archival, protected object counts |
| `access` | IP allowlist, lockout, sessions, password policy, identity providers, service accounts (names, ids, last login, roles), role catalogue, SSO groups |
| `clusters` | CDM clusters: version, health, encryption at rest, air gap, quorum, support tunnel, end of support |
| `threat` | Threat Monitoring enablement for cloud, M365 and CDM roots, and object-level enablement |
| `detection` | Anomaly alert settings, threat hunt history, webhooks and event/audit forwarding |
| `dhrc` | RSC's own Data Health / Resilience Cockpit scores, used to cross-check this report's counts |
| `recovery` | Recovery plans: status, type, last run outcome, schedule |
| `offsite` | Which SLA domains replicate to another cluster or archive to cloud, which cluster each archive target belongs to, and whether archives are immutable |

Scored areas: Identity, MFA, Quorum, Access, RBAC, Immutability, Coverage, Platform, Anomaly Detection,
Threat Monitoring, Sensitive Data Discovery, Alerting, Recovery.

Detection capabilities (the "Are you prepared?" page): Anomaly Detection, Threat Monitoring, Sensitive Data
Discovery. Threat hunting is not scored; the page carries one unscored line on hunt history.

## Customer guide

Plan on about 30 minutes plus review time.

### 1. Prerequisites

- **Either** PowerShell **or** Python. You only need one.
  - PowerShell: `Invoke-CyberReadiness.ps1`, no modules to install. Tested on PowerShell 7 only. It is written
    to also run on Windows PowerShell 5.1 but that is not yet verified.
  - Python: Python 3 (tested on 3.12 only) and `pip install requests`.
- Network access from the machine to your RSC instance URL (the host in the service account file).
- An RSC user who can create service accounts and roles.

You do not need Chrome, fonts or any Rubrik assets. Those are only used to render the report.

### 2. Create a dedicated service account

Use a new account for this assessment and delete it when you are done.

1. In RSC, go to the user management area and create a **service account**.
2. Assign a role that can only read. See [Choosing a role](#choosing-a-role).
3. Download the JSON file. It contains `client_id`, `client_secret` and `access_token_uri`.
4. Store the file somewhere private (for example `~/.rubrik/assessment.json`). **Do not email it or put it in a shared folder.** The client secret grants API access.

### Choosing a role

**Option 1 (try first): the built-in "Read-only Administrator" role.** It needs no custom design.
It is not confirmed to cover every query in this toolkit. Preflight tells you if it does not.

**Option 2: a custom role with view permissions only.** Create a role with these permissions, scoped to
**all objects**:

| Collector | Permissions likely needed |
|---|---|
| identity, access | VIEW_USER, VIEW_USER_MANAGEMENT, VIEW_ROLE, VIEW_SERVICE_ACCOUNT, VIEW_ACCESS, VIEW_SECURITY_SETTINGS, VIEW_SECURITY_POLICY |
| mfa, quorum | VIEW_SECURITY_SETTINGS, VIEW_TPR_CONFIGURATION, VIEW_TPR_POLICY, VIEW_TPR_REQUEST, VIEW_ORGANIZATION |
| inventory | VIEW_INVENTORY, VIEW_CLUSTER, VIEW_DASHBOARD |
| sla | VIEW_SLA, VIEW_ARCHIVAL_LOCATION |
| clusters | VIEW_CLUSTER, VIEW_CDM_SYS_CONFIG |
| threat, dhrc | VIEW_ANOMALY_DETECTION_RESULTS, VIEW_THREAT_HUNT_RESULTS, VIEW_DATA_SECURITY_POSTURE_RESULTS, VIEW_DATA_CLASS_GLOBAL, VIEW_FEATURE_ENABLEMENT, VIEW_DASHBOARD |

- Add nothing that does not start with `VIEW`.
- Do not scope the role to a subset of the hierarchy. A narrow scope makes coverage counts understate what
  exists, and the report cannot tell the difference.
- This mapping is inferred from permission names and is **untested** against a narrow role. See
  [minimum-role.md](minimum-role.md).

### 3. Get the toolkit

Your Rubrik contact will give you the toolkit as a zip or repository access.

```
cd rubrik-cyber-readiness-public
```

Python only: `pip install requests`. PowerShell needs nothing more.

The PowerShell script (`Invoke-CyberReadiness.ps1`) and the Python collector (`collect.py`, `preflight.py`) do
the same job and write the same `bundle.json`, `bundle.redacted.json` and `redaction-map.json`. Pick one. The
assessor renders the report from either, exactly the same way.

On Windows, if script execution is blocked, run PowerShell commands as
`powershell -ExecutionPolicy Bypass -File .\Invoke-CyberReadiness.ps1 ...`.

### 4. Run preflight

PowerShell:

```
./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Preflight
```

Python:

```
python3 preflight.py --sa ~/.rubrik/assessment.json
```

Preflight authenticates, runs every collector once, and prints one line per section.

```
authenticated to https://<your-instance>.my.rubrik.com
ok    identity
ok    mfa
FAIL  access.rolePermissions: <reason>
...
```

| Result | Meaning | Action |
|---|---|---|
| `all collectors can read`, exit 0 | The role is sufficient | Continue |
| `FAIL <collector>.<section>`, exit 1 | A query was denied or failed | Add the missing view permission, or continue and accept that the area is "not assessed" |

### 5. Collect with redaction

PowerShell:

```
./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Customer ACME -Redact
```

Python:

```
python3 collect.py --sa ~/.rubrik/assessment.json --customer ACME --redact
```

| PowerShell | Python | Meaning |
|---|---|---|
| `-ServiceAccount` | `--sa` | Path to the service account JSON (required) |
| `-Customer` | `--customer` | Short label used in the output folder and report (required) |
| `-Redact` | `--redact` | Also write the redacted bundle and the redaction map |
| `-Out` | `--out` | Output directory. Default `~/CyberReadiness` (PowerShell) or `~/.local/share/cyber-readiness` (Python) |
| `-Preflight` | (separate `preflight.py`) | Check what the role can read and write nothing. Exit 1 if anything was denied |

Files written to `<out>/<customer>/`:

| File | Send it? | Contents |
|---|---|---|
| `bundle.json` | **No** | Raw collected data, real names |
| `bundle.redacted.json` | **Yes, after review** | Same data with names and identifiers pseudonymized |
| `redaction-map.json` | **No** | The mapping from pseudonyms back to real names. Only you can read the report in real terms. |

A collector that fails is recorded and the run continues. Nothing aborts the whole collection.

### 6. Review before sending

Open `bundle.redacted.json` in a text editor and search for anything that should not leave your organization:
hostnames, domain names, usernames, project names, internal URLs. Redaction is name-based. See
[Data handling and privacy](#data-handling-and-privacy) for exactly what is and is not covered.

Send **only** `bundle.redacted.json`.

### 7. Clean up

- Delete the service account in RSC.
- Delete or securely store the service account JSON file.
- Keep `redaction-map.json`. You need it to translate the report's pseudonyms back to real objects.

## Assessor guide

### Requirements

| Requirement | Why |
|---|---|
| Python 3.12 | Tested version |
| Google Chrome or Chromium | Prints the HTML report to PDF. Found automatically on macOS, Linux and Windows. Set `CHROME` to override. |
| Brand assets | None needed. The report is neutral by default; see [Branding the report](#branding-the-report). |
| `pip install reportlab` | Only for `--style classic`, which needs no browser |

The report uses system fonts and a text mark unless you brand it. The optional fonts in `assets/fonts/` are
licensed under the SIL Open Font License (the license files sit beside them).

### Branding the report

The repository ships a neutral report: plain palette, system fonts, a generic "Confidential" footer and a text
mark. Your look lives in a local `brand/` folder. Git ignores it, so it cannot be committed by accident.

| File in `brand/` | What it does |
|---|---|
| `logo.svg` | Logo for the `brief` style (default), drawn at 58 x 24 pt |
| `logo.png` | Logo for the `classic` style, square, drawn at 0.5 in |
| `brand.json` | Palette, footer, header, text mark, PDF author, bundled fonts. Every key is optional |

Copy [docs/brand.example.json](brand.example.json) to `brand/brand.json` and edit it. Palette keys are `ink`,
`muted`, `soft`, `accent`, `accent2`, `card_bg`, `card_line`, `rule`, `red` and `amber`, each `#RRGGBB`. A bad
value or a malformed file is ignored and the neutral default is used. `bundled_fonts: true` embeds the Open
Font License fonts in `assets/fonts/`. Set `CRR_BRAND_DIR` to use a different folder, for example one per brand.

The older `assets/rubrik-logo-primary-linear.svg` and `assets/rubrik-logo.png` paths still work as a fallback.

Every render prints one `logo:` line, so check it before the PDF goes to a customer:

```
logo: using /path/to/assets/rubrik-logo-primary-linear.svg
logo: not found, using the text mark. To brand the report, add /path/to/assets/rubrik-logo-primary-linear.svg
```

A file that exists but is not an SVG is reported and skipped. Only add the logo to a copy of the toolkit you
run yourself; the customer collector never needs it.

### Render the report

```
python3 render_pdf.py --bundle /path/to/bundle.redacted.json
```

| Flag | Meaning |
|---|---|
| `--bundle` | Path to `bundle.json` or `bundle.redacted.json` (required) |
| `--previous` | An earlier bundle from the same customer. Adds a "Progress since last run" page. |
| `--style` | `brief` (default, HTML printed by Chrome) or `classic` (reportlab, no browser) |

`report.pdf` is written next to the bundle. In `brief` style, `report.html` is also left beside it.

### Reading a redacted report back to the customer

Findings name objects by pseudonym. The customer holds `redaction-map.json`, so they translate. Do not ask
for the map. If you need a specific object identified, ask them to look it up.

### Running it yourself

If you have credentials for the tenant (a lab, or a customer who gave you access directly), run the three
steps in sequence:

```
python3 preflight.py --sa /path/to/sa.json
python3 collect.py   --sa /path/to/sa.json --customer ACME --redact
python3 render_pdf.py --bundle ~/.local/share/cyber-readiness/ACME/bundle.json
```

or, collecting with PowerShell (the bundle lands in `~/CyberReadiness` by default):

```
./Invoke-CyberReadiness.ps1 -ServiceAccount /path/to/sa.json -Preflight
./Invoke-CyberReadiness.ps1 -ServiceAccount /path/to/sa.json -Customer ACME -Redact
python3 render_pdf.py --bundle ~/CyberReadiness/ACME/bundle.json
```

## Data handling and privacy

### What leaves the customer environment

Only what they choose to send. The recommended path is `bundle.redacted.json`.

### What the toolkit reads

Configuration and inventory metadata through RSC GraphQL queries: users and roles, security settings, SLA
domains, cluster properties, object inventory and protection status, detection enablement and results. No
query reads backup contents, snapshot data or file contents. Service account names, client ids and last-login
times are read; client secrets are not.

### What redaction does

Replaced with stable pseudonyms:

- User emails and ids
- Service account names
- IP allowlist entries
- Names of objects, hosts, clusters, SLAs, roles, policies and cloud accounts
- Offsite SLA, archive target and replication cluster names, and recovery plan names

Kept, because scoring needs them:

- Counts, booleans, dates and object types
- The built-in role names (for example Administrator and Owner)

Free-text fields such as role descriptions are withheld. Findings and scores are identical before and after
redaction. This is covered by tests.

### What redaction does not do

Redaction is **name-based**. A sensitive value in a field the toolkit does not know about would not be
redacted. The customer must read `bundle.redacted.json` before it leaves. Tier-0 detection and test/dev
detection work from names, so the redacted bundle carries the same classification signals, not the names.

### Credentials

- Use a dedicated service account and delete it afterwards.
- The JSON file holds a client secret. Keep it out of email, chat and shared folders.
- The toolkit never writes the secret to its output.

## Reading the report

| Section | What it tells you |
|---|---|
| **1. Are you prepared?** | The three detection capabilities, each scored by what RSC actually shows for the tenant. A capability with no data scores zero. |
| **2. Where you stand** | Scores by area, RSC's own resilience scores alongside, and the priority findings with a fix-now / process grouping |
| **3. Roadmap** | Projected score, NIST CSF view, and the 30/60/90 day plan |
| **Appendix. Cluster inventory** | Every cluster with its software version, status, end-of-support state, and whether it archives to Rubrik Cloud Vault (RCV). A one-line summary also sits under "Where you stand". |
| **Appendix** | Every finding with evidence, steps, documentation links and framework tags, then the method and its limits |

### Reading the cluster inventory

- **RCV is identified by archival location type** (`RCS_AZURE`, `RCV_AWS`, `RCV_GCP`), never by name. RSC reports
  RCV on Azure as `RCS_AZURE`. Names are pseudonymized in a redacted bundle, so a name test would find nothing.
- **"Objects under RCV SLAs" is an upper bound.** The archive mapping is per cluster but the object count is per
  SLA. An SLA that spans several clusters counts all its objects against each cluster that archives it to RCV. Use
  the number to rank clusters, and confirm the exact figure in RSC before quoting it.
- **"Not known" is not "No".** Bundles collected before cluster ids were recorded on archive targets cannot say
  which cluster archives where. The report shows "Not known" and "n/a" for those, and the summary line says why.
  Re-collect to get the answer.
- **"Not reported" end of support is not "Supported".** RSC returns `EOS_STATUS_UNKNOWN` for most clusters on the
  tenants tested. The four values RSC can return are Supported, Plan upgrade, Out of support and Unknown.
- **Versions are shown whole** (for example `9.6.1-p1-33607`) and grouped by base version in the summary.

### How scoring works

Each area starts at 100 and loses 25, 15, 7 or 3 points per critical, high, medium or low finding.
Scores show **relative gaps**. They are not a benchmark and not comparable across customers.

Thresholds are guidance values, not Rubrik limits. They are named constants at the top of `score.py`:

| Threshold | Value |
|---|---|
| Stale account | 90 days |
| MFA remember window | 24 hours |
| Account owners | 2 or fewer |
| Quorum approvers | 2 or more |
| Minimum password length | 12 characters |
| Admin share of users | Medium above 25%, high above 50% |

### Things to say out loud

- **Object counts are RSC object records, not distinct workloads.** VM figures are collapsed to one record
  per VM. RSC's own resilience scores appear beside this report's scores, and the two do not reconcile.
- **Likely Tier-0 (finding C-4)** is inferred from RSC object types and VM names. It misses assets with
  opaque names. Ask the customer for their real Tier-0 list.
- **Test/dev detection** matches names such as dev, test, qa, uat and staging. It is a heuristic.
- **NIST CSF and HIPAA tags** are the author's judgment and have not been reviewed by compliance. They are
  not a statement of compliance.
- **Edition grouping.** Findings are grouped Fix now, Process, Enterprise Edition, or Edition unconfirmed. A
  finding is only called Enterprise Edition when `editions.py` marks it confirmed with a source. **None are
  confirmed today.** Do not present anything in a report as an upgrade benefit until entitlement is checked
  against the price book.
- **Roadmap dates and the projected score** order the work. They are not commitments.
- **"Not assessed"** means a collector failed or was denied. It is never scored as clean.

## Alerting and notifications

Cyber recovery is a team sport. Backup and infrastructure teams see RSC every day. The security team, the
SOC and the incident commander usually do not. If detections only appear in the RSC console, the people who
can contain an attack find out when someone from the backup team tells them, which is late.

This assessment treats notification routing as a readiness question, not a settings checklist. The test is:
**when RSC detects something at 2am, who is paged, and are they the people who would act on it?**

### What the assessment checks

| Finding | Rule | Raised when | Severity |
|---|---|---|---|
| Anomaly alerts are turned off | T-3 | Anomaly alerting is disabled | High |
| No event or audit forwarding | T-4 | No enabled webhook exists | Medium |
| Webhooks carry neither events nor audit logs | T-4 | Webhooks are enabled but none subscribes to events or audits | Medium |
| Webhook deliveries are failing | T-5 | An enabled webhook reported a delivery error on its last failure | Medium |
| No one receives RSC email | T-6 | Users were counted and none has email notifications on | Medium |
| Event webhook payload omits threat detail | T-7 | An enabled event webhook uses a template that does not include `eventInfo` | Medium |
| Every event webhook is Critical only | T-8 | All enabled event webhooks are limited to Critical severity | Medium |
| CDM clusters send no syslog and no SNMP traps | T-9 | A connected CDM cluster has no syslog export rule and no SNMP trap receiver | Medium |

The "Alerting" area score and the Anomaly Detection capability card on page 2 draw on these.

**How the checks treat what they cannot read.** If a query is denied, a template cannot be fetched, or a cluster
is offline, that part is unknown and is never reported as a gap. The report will not tell the customer that
something is misconfigured when the toolkit simply could not look. The new checks also fail independently, so a
denied email query does not hide the webhook findings.

**What is stored.** Only counts. Recipient addresses, webhook names and URLs, syslog hostnames and trap receiver
addresses are never written to the bundle. The SNMP community string is a credential and is never requested.

### What the assessment cannot check

A clean Alerting score means webhooks exist, deliver, and carry usable detail. It does **not** mean the right
people receive the right alerts. The toolkit cannot see:

- **Who is on the other end.** A webhook that posts to a mailbox nobody reads passes every check.
- **Who has email turned on.** T-6 only fires when nobody does. It cannot tell whether the people with email on
  are the security team or the incident commander.
- **What a webhook's severity and event filters leave out**, beyond the Critical-only case in T-8. It does not
  judge whether the chosen event types match the team's needs.
- **Whether a custom template is correct**, only whether it includes `eventInfo`.
- **Syslog and SNMP delivery.** T-9 checks that a destination is configured, not that it is reachable or monitored.
- **Whether the receiving team has a runbook** for what to do on an alert.

Ask these in the readout. They are discovery questions, and often the most valuable ones in the engagement.

### Who should receive what

Route by role. The same alert should not go to everyone.

| Audience | Needs | Typical channel |
|---|---|---|
| Backup and infrastructure team | Job failures, SLA violations, cluster health | Email digest, ticketing |
| Security operations (SOC) | Anomaly, Threat Monitoring, threat hunt matches, audit logs, identity alerts | Webhook to SIEM |
| Incident commander and on-call | Critical anomaly and ransomware events only | Webhook to paging tool |
| Identity team | Identity alerts and identity security violations | Webhook or email |
| Compliance and audit | Audit logs | Webhook to log archive or SIEM |

### Configuration guidance

Configure these in RSC under **Settings > Notifications**. Product documentation is linked at the end of this
section.

**Webhooks (primary path for the security team)**

- Send **Events and audit logs** to the SIEM or paging tool. Webhooks are how RSC reaches platforms such as
  Microsoft Sentinel, where Rubrik events can be correlated with other data and trigger playbooks.
- For threat detection, select **Threat Monitoring, threat intel, and threat hunting** so all three scenarios
  are covered.
- **The export template must include `eventInfo`.** Preview the output to confirm it. Rubrik's documentation
  notes that the default PagerDuty template does not include it.
- Be aware of the event cap. RSC sends one webhook event per match for Threat Monitoring and threat hunting,
  but if a snapshot produces more than 500 matches the per-match events are dropped and only the summary event
  is sent. A SIEM that only counts per-match events will under-report a large incident.
- Identity events need an Identity Resilience license to stream identity change events from Entra ID and
  Active Directory.
- Test every webhook after creating it, then re-check delivery status regularly. T-5 will tell you about
  failures that already happened.

**Email**

- The default is **Receive no email**. A user who is never configured never gets mail.
- Set event type, object type, audit type and severity per user. The default severity is Critical.
- For anomaly detection, RSC emails the specified recipients with a Warning (low levels of detected
  encryption) or Critical (high levels) severity. Make sure the recipients include security, not only the
  backup team.
- Email is sent from `noreply@rubrik.com`. Allow-list it in the spam filter.
- Per-match Threat Monitoring and threat hunting events do **not** trigger email notifications. Those need
  separate configuration, so email alone will miss them.
- For identity alerts and violations, select the **Identity Alert** and **Identity Security Violation** event
  types and all severity levels.

**CDM clusters**

- Syslog export and SNMP are configured separately for CDM clusters. This toolkit does not assess them.

### Questions to ask the customer

1. If a Critical anomaly fires at 2am on a Saturday, who is notified and how?
2. Does the SOC see RSC events in the SIEM, or only when the backup team escalates?
3. When did anyone last test the path end to end?
4. Who owns the webhook endpoints? What happens when a certificate expires?
5. Is the incident commander on the Critical alert path, or does that depend on someone forwarding it?
6. Do the people receiving alerts have a runbook, and has it been rehearsed?
7. Are identity events (Entra ID and Active Directory) flowing to the same place?
8. Which RSC users have email notifications turned on? Have any been left at the default?

### Reference documentation

| Topic | Link |
|---|---|
| Notifications overview | https://docs.rubrik.com/en-us/saas/saas/notifications.html |
| Webhooks | https://docs.rubrik.com/en-us/saas/saas/common/webhooks.html |
| Threat detection webhooks | https://docs.rubrik.com/en-us/saas/saas/common/webhooks_threat_detection.html |
| Email notifications | https://docs.rubrik.com/en-us/saas/saas/common/email_notifications.html |
| Configuring email notifications | https://docs.rubrik.com/en-us/saas/saas/configuring_email_notifications.html |
| Enabling Anomaly Detection | https://docs.rubrik.com/en-us/saas/saas/enabling_anomaly_detection.html |

## Re-running and tracking progress

Keep the first bundle. Collecting again overwrites `bundle.json`, so copy the first one elsewhere first.

```
python3 collect.py    --sa /path/to/sa.json --customer ACME --redact
python3 render_pdf.py --bundle <out>/ACME/bundle.redacted.json --previous /path/to/first/bundle.json
python3 delta.py /path/to/first/bundle.json <out>/ACME/bundle.json    # text-only comparison
```

If the customer collects with PowerShell, replace the first line with
`./Invoke-CyberReadiness.ps1 -ServiceAccount /path/to/sa.json -Customer ACME -Redact`. Bundles from either
collector can be compared with each other.

Both bundles are scored with the current rules. A finding counts as resolved only if its area was assessed in
both runs, so a denied query or a failed collector never shows up as progress. The score shown is averaged over
the areas both runs assessed. **Nothing checks that the two bundles belong to the same customer.** Check this
yourself.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Auth failed (401 ...)` | Wrong or expired service account file, or the account was deleted | Download a fresh JSON file |
| `Auth failed (403 ...)` | Account lacks API access | Check the role and that the account is enabled |
| `KeyError: 'client_id'` or `access_token_uri` | The file is not a service account JSON | Use the file RSC generated |
| Connection error or timeout | Network egress to the RSC host is blocked | Allow outbound HTTPS to the instance host |
| `FAIL <collector>...` in preflight | A view permission is missing | Add it, or accept "not assessed" for that area |
| `retries exhausted` | Repeated 429 or 5xx from RSC | Retry later. The client already backs off 3 times. |
| A whole area shows "not assessed" | Collector failed or was denied | Run preflight to see which query and why |
| Coverage looks too low | Role scoped to part of the hierarchy | Re-scope the role to all objects |
| `Chrome not found at ...` | No Chrome or Chromium on the usual paths or on `PATH` | Install one, set `CHROME` to its full path, or use `--style classic` |
| `Chrome did not finish within 180 seconds` | Very large report or a hung Chrome | Close other Chrome instances and retry |
| Text "Rubrik" mark instead of the logo | The logo is not in the repository. The render prints a `logo:` line saying what it found | See [Branding the report](#branding-the-report) |
| Plain system fonts | `bundled_fonts` is not set in `brand/brand.json`, or `assets/fonts/` is incomplete | Set it, or restore `assets/fonts/` |
| `...cannot be loaded because running scripts is disabled` (PowerShell) | Windows execution policy | `powershell -ExecutionPolicy Bypass -File .\Invoke-CyberReadiness.ps1 ...` |
| `ModuleNotFoundError: requests` | Dependency missing | `pip install requests` |
| `ModuleNotFoundError: reportlab` | Using `--style classic` | `pip install reportlab` |

## Known limits

- **The minimum role is untested.** The read-only role guidance is inferred from permission names. The
  toolkit has been run only with a full-admin lab account.
- **Not yet run against a Business Edition tenant** or with a narrow role.
- **RBAC rules** match the built-in role names Administrator and Owner. They do not inspect what custom roles
  can do beyond the effective-permission read, which is itself untested with a narrow role. If the role
  catalogue cannot be read, the collector falls back to names and records an error stub. An unreadable SSO
  group list records an error stub and rule R-5 is skipped.
- **Alerting checks confirm plumbing, not people.** The toolkit checks that webhooks exist, deliver, carry
  usable detail and are not Critical-only, that someone has email on, and that CDM clusters have a syslog or SNMP
  destination. It cannot tell who receives the alerts or whether they act. The alerting queries were each run
  against a live tenant, but the full `collect.py` run with the new collectors has not been done, and none of it
  has been run with a narrow role. See [Alerting and notifications](#alerting-and-notifications).
- **Webhook records in older bundles.** Bundles collected before this change stored raw webhook records, including
  webhook names. Redaction now drops them, but do not send an unredacted older bundle to anyone.
- **Redaction is name-based.** See above.
- **Chrome discovery on Linux and Windows is untested.** The toolkit looks for Chrome or Chromium on the usual
  paths and on `PATH`, but it has only been run on macOS. Set `CHROME` if it is not found.
- **No Rubrik logo.** The logo is a trademark and is not included. See
  [Branding the report](#branding-the-report).
- **Python 3.12 only** has been tested.
- **Redaction scope.** Bundles collected before the offsite and recovery redaction fix carried SLA names,
  archive target names, replication cluster names and recovery plan names in `bundle.redacted.json`. Do not send
  a redacted bundle made by an older version. A live scan of current output found no raw identifying value
  surviving in either collector's redacted bundle.
- **Tier-0 evidence text can shift after redaction.** Tier-0 name matching runs on pseudonyms in a redacted
  bundle, so the "by name only" count in that finding's evidence string can differ from the raw bundle's by a
  few. Scores and finding severities are unchanged.
- **The PowerShell collector is tested on PowerShell 7 only.** Its raw and redacted bundles matched the Python
  collector's against both a mock RSC and a live lab tenant, but it has not been run on Windows PowerShell 5.1
  or with a narrow role. Run `-Preflight` first.
- **No license is set** in this repository. Clarify terms before wider distribution.

## Development

```
python3 tests/run_tests.py
```

130 tests, no network and no tenant needed. They cover scoring, redaction (including score parity before and
after), delta logic, roadmap, edition grouping, framework tags, Tier-0 detection, HTML rendering and Chrome
printing.

The customer runs the PowerShell redactor, so a name that survives there leaks in the one file they send.
`tests/test_powershell_redaction.py` runs the real script against the mock and fails if any real cluster, SLA,
archive or user name is left in the redacted bundle. It is part of `run_tests.py` and skips itself when `pwsh` is
not installed, so on a machine without it the check silently does not run.

Full PowerShell parity check (needs `pwsh`). Run the mock RSC, collect with both collectors, and diff the bundles:

```
python3 tests/mock_rsc.py 18080 &
python3 collect.py --sa tests/.mock-sa.json --customer PYREF --redact --out /tmp/parity
pwsh -File ./Invoke-CyberReadiness.ps1 -ServiceAccount tests/.mock-sa.json -Customer PSREF -Redact -Out /tmp/parity
python3 tests/compare_bundles.py /tmp/parity/PYREF/bundle.json /tmp/parity/PSREF/bundle.json --unordered
python3 tests/compare_bundles.py /tmp/parity/PYREF/bundle.redacted.json /tmp/parity/PSREF/bundle.redacted.json --mask --unordered
```

Both comparisons should print `identical`. Set `MOCK_DENY_PERMS=1` when starting the mock to exercise the
role-permissions fallback. Any collector change must be made in both `collectors/` and
`Invoke-CyberReadiness.ps1`.

Adding a collector:

1. Add `collectors/<name>.py` with a `collect(client)` function. Isolate each sub-query so one failure
   records an error stub instead of raising.
2. Register it in `COLLECTORS` in `collect.py`.
3. Add rules in `score.py`, wording in `report_text.py`, and framework tags in `frameworks.py`.
4. Add the name-bearing fields to `redact.py` and a case to `tests/test_redact.py`.
5. Use queries only. Never add a mutation.

## Repository layout

| Path | Purpose |
|---|---|
| `rsc_client.py` | Auth, retries, pagination |
| `collectors/` | One module per area. Each isolates its own failures. |
| `collect.py` | Runs all collectors and writes the bundle |
| `preflight.py` | Access check |
| `Invoke-CyberReadiness.ps1` | PowerShell equivalent of `collect.py`, `preflight.py` and `redact.py` in one script |
| `tests/mock_rsc.py`, `tests/compare_bundles.py` | Fake RSC and bundle diff for Python/PowerShell parity |
| `redact.py` | Pseudonymizes a bundle |
| `score.py` | Rules and scores |
| `editions.py` | Edition entitlement per finding, with source |
| `frameworks.py` | NIST CSF and HIPAA tags |
| `tier0.py` | Likely Tier-0 asset detection |
| `rbac.py` | Role and permission analysis |
| `capabilities.py` | The four detection capabilities |
| `roadmap.py` | 30/60/90 day phases and projected score |
| `remediation.py` | Fix steps and documentation links |
| `posture.py` | Which areas were assessed, shared by report and delta |
| `delta.py` | Compare two bundles |
| `report_text.py` | Wording shared by both layouts |
| `render_pdf.py` | Entry point. `--style classic` is the reportlab layout. |
| `render_html.py` | The brief layout, printed to PDF with headless Chrome |
| `docs/minimum-role.md` | Access guidance (untested) |
| `tests/` | Test suite |
