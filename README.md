# Rubrik Cyber Readiness Assessment

A read-only check of your Rubrik Security Cloud (RSC) tenant. You run a script that reads your configuration,
review the file it produces, and send that one file to your Rubrik team. They turn it into a PDF with ranked
findings, evidence, fix steps and a 30/60/90 day roadmap.

- **Read-only.** The script runs queries only. It changes nothing in your tenant.
- **You stay in control.** You review the file before anything leaves your organization.
- **No backup data.** It reads settings and inventory. It never reads backup contents, snapshots or files.

**Time needed:** about 30 minutes, plus your review time.

## The process

| # | Step | Who | Time |
|---|---|---|---|
| 1 | [Create a service account](#1-create-a-service-account) | Your RSC admin | 5 min |
| 2 | [Run preflight](#2-run-preflight) | You | 2 min |
| 3 | [Collect](#3-collect) | You | 5 to 15 min |
| 4 | [Review the file](#4-review-the-file) | You and your security team | Your call |
| 5 | [Send it](#5-send-the-file) | You | 1 min |
| 6 | [Clean up](#6-clean-up) | You | 2 min |
| 7 | Receive the PDF | Your Rubrik team | After they render it |

## Before you start

You need:

- **PowerShell 7** or **Python 3**. Either one works. You do not need both.
- Network access from your machine to your RSC address (the host in the service account file).
- An RSC user who can create service accounts and roles.

You do **not** need Chrome, fonts or any Rubrik assets. Your Rubrik team uses those to build the PDF.

> **Windows PowerShell 5.1 is not yet verified.** If your machine only has the older "Windows PowerShell"
> (blue window, `powershell.exe`), install PowerShell 7 or use the Python option.

Get this folder from your Rubrik contact (zip or repository), then open a terminal inside it:

```
cd rubrik-cyber-readiness
```

Python users also run `pip install requests`. PowerShell needs nothing else.

If Windows blocks the script, start it with
`powershell -ExecutionPolicy Bypass -File .\Invoke-CyberReadiness.ps1 ...`.

## 1. Create a service account

Make a **new** service account just for this assessment. You will delete it at the end.

1. In RSC, open user management and create a **service account**.
2. Give it a role that can only read. Try the built-in **Read-only Administrator** role first.
3. Download the JSON file. It holds a `client_id`, a `client_secret` and an `access_token_uri`.
4. Save it somewhere private, for example `~/.rubrik/assessment.json`.

**Do not email the JSON file or put it in a shared folder.** The client secret grants API access.

If Read-only Administrator turns out not to be enough, preflight (next step) tells you. You can then use a custom
role with view permissions only. The permission list is in [docs/minimum-role.md](docs/minimum-role.md) and
[docs/assessor-guide.md](docs/assessor-guide.md#choosing-a-role). Scope the role to **all objects**. A narrow
scope makes coverage look lower than it is, and the report cannot tell the difference.

## 2. Run preflight

Preflight signs in and checks that the account can read everything. It writes nothing.

PowerShell:

```
./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Preflight
```

Python:

```
python3 preflight.py --sa ~/.rubrik/assessment.json
```

You will see one line per area:

```
authenticated to https://<your-instance>.my.rubrik.com
ok    identity
ok    mfa
FAIL  access.rolePermissions: <reason>
```

| Result | What it means | What to do |
|---|---|---|
| `all collectors can read`, exit code 0 | The role is enough | Go to step 3 |
| `FAIL <area>`, exit code 1 | The role cannot read that area | Add the missing view permission, or continue and accept that the area shows as "not assessed" |

## 3. Collect

PowerShell:

```
./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Customer ACME -Redact
```

Python:

```
python3 collect.py --sa ~/.rubrik/assessment.json --customer ACME --redact
```

Replace `ACME` with a short name for your organization.

| PowerShell | Python | Meaning |
|---|---|---|
| `-ServiceAccount` | `--sa` | Path to the service account JSON (required) |
| `-Customer` | `--customer` | Short label for the output folder and report (required) |
| `-Redact` | `--redact` | Also write the redacted file and the redaction map. Always use this. |
| `-Out` | `--out` | Output folder. Default `~/CyberReadiness` (PowerShell) or `~/.local/share/cyber-readiness` (Python) |

If one area fails, it is recorded and the run continues.

It writes three files to `<out>/<customer>/`:

| File | Send it? | What it is |
|---|---|---|
| `bundle.redacted.json` | **Yes, after your review** | Your data with names and identifiers replaced by pseudonyms |
| `bundle.json` | **No** | Raw data with real names |
| `redaction-map.json` | **No** | Translates pseudonyms back to real names. Keep it. |

## 4. Review the file

Open `bundle.redacted.json` in a text editor and search for anything that should not leave your organization:
hostnames, domain names, usernames, project names, internal URLs.

Redaction replaces names it knows about. It does not catch everything, so this review is required, not optional.

| Replaced with pseudonyms | Kept, because scoring needs them |
|---|---|
| User emails and ids | Counts, true/false settings, dates |
| Service account names | Object types |
| IP allowlist entries | Built-in role names such as Administrator and Owner |
| Names of objects, hosts, clusters, SLAs, roles, policies and cloud accounts | |
| Offsite SLA, archive target and replication cluster names, and recovery plan names | |

Free-text fields such as role descriptions are removed.

## 5. Send the file

Send **only** `bundle.redacted.json` to your Rubrik contact.

Never send `bundle.json`, `redaction-map.json` or the service account JSON.

## 6. Clean up

- Delete the service account in RSC.
- Delete the service account JSON file.
- Delete `bundle.json`, or store it securely.
- **Keep `redaction-map.json`.** The report uses pseudonyms, and you need the map to read it in real terms.

## 7. Read your report

Your Rubrik team returns a PDF. Findings refer to objects by pseudonym, such as `obj-d8f790d6`. Look them up in
your `redaction-map.json` to find the real object.

The PDF contains:

- An executive summary with a posture score
- Four detection capabilities: Anomaly Detection, Threat Monitoring, Threat Hunting, Sensitive Data Discovery
- Scores for 14 areas, with ranked findings, evidence and fix steps
- A 30/60/90 day roadmap

Scores start at 100 per area and drop for each finding. They show relative gaps and are not a benchmark. Framework
tags (NIST CSF, HIPAA) are a guide for the conversation and not a statement of compliance.

## What the script reads

Configuration and inventory only, through RSC GraphQL queries:

| Area | Reads |
|---|---|
| Identity, MFA, access | Users, roles, MFA settings, IP allowlist, lockout, password policy, identity providers, service account names and last login |
| Quorum | Quorum (TPR) configuration and policies |
| Inventory, SLA | Protected and unprotected objects, SLA domains, retention lock, replication, archival |
| Clusters | CDM cluster version, health, encryption at rest, air gap, support tunnel |
| Threat, detection | Threat Monitoring enablement, anomaly alert settings, threat hunt history, webhooks |
| Recovery, offsite | Recovery plans and run outcomes, which SLAs replicate or archive offsite |
| Resilience scores | RSC's own Data Health scores, used to cross-check the report |

It does not read backup contents, snapshot data or file contents. It reads service account names, client ids and
last-login times. It never reads or writes client secrets.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Auth failed (401 ...)` | Wrong or expired service account file, or the account was deleted | Download a fresh JSON file |
| `Auth failed (403 ...)` | Account lacks API access | Check the role and that the account is enabled |
| `KeyError: 'client_id'` or `access_token_uri` | The file is not a service account JSON | Use the file RSC generated |
| Connection error or timeout | Outbound HTTPS to RSC is blocked | Allow outbound HTTPS to your RSC host |
| `FAIL <area>` in preflight | A view permission is missing | Add it, or accept "not assessed" for that area |
| `retries exhausted` | Repeated 429 or 5xx from RSC | Try again later |
| A whole area shows "not assessed" | The query failed or was denied | Run preflight to see which one and why |
| Coverage looks too low | Role scoped to part of the hierarchy | Re-scope the role to all objects |
| `...running scripts is disabled` (PowerShell) | Windows execution policy | `powershell -ExecutionPolicy Bypass -File .\Invoke-CyberReadiness.ps1 ...` |
| `ModuleNotFoundError: requests` | Dependency missing | `pip install requests` |

## Known limits

- **Not yet verified on Windows PowerShell 5.1.** Use PowerShell 7 or Python.
- **Minimum role not fully confirmed.** Read-only Administrator may not cover every query. Preflight tells you.
- **Redaction is name-based.** Review the file before you send it.
- **Use the current version.** Files made by older versions of this toolkit can contain SLA, archive target and
  recovery plan names in the "redacted" file. Do not send a redacted file made by an older version.

## For your Rubrik team

Rendering the PDF, reading scores, alerting guidance, re-running to track progress, and development notes are in
[docs/assessor-guide.md](docs/assessor-guide.md).
