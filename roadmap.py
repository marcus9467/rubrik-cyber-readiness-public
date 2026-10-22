"""30/60/90 day roadmap and projected scores, built from scored findings.

Phase rules (author's guidance, not a Rubrik standard):
  30 days  fix_now findings rated critical or high (configuration only, no project needed)
  60 days  remaining fix_now findings, and process findings rated critical or high
  90 days  remaining process findings

Projected scores assume every finding in the phases up to that point is fully resolved and nothing new
appears. Edition has no effect on phase or score: every finding is phased and projected the same way.
"""
from score import SEVERITY_PENALTY

from capabilities import ceilings
from frameworks import CSF_NAMES

PHASES = (30, 60, 90)


def csf_rows(findings):
    """Per CSF function: (name, number of findings, worst severity or None), from the findings alone."""
    order = ["critical", "high", "medium", "low", "info"]
    out = []
    for code, name in CSF_NAMES.items():
        fs = [f for f in findings if (f.get("framework") or {}).get("csf") == code and f["severity"] != "info"]
        worst = min((order.index(f["severity"]) for f in fs), default=None)
        out.append((name, len(fs), order[worst] if worst is not None else None))
    return out


def phase_of(f):
    if f["severity"] == "info":
        return None
    b, high = f["bucket"], f["severity"] in ("critical", "high")
    if b in ("fix_now", "visibility"):
        return 30 if high else 60
    if b == "process":
        return 60 if high else 90
    return 90


def plan(findings):
    """Findings grouped by phase: {30: [...], 60: [...], 90: [...]}."""
    out = {30: [], 60: [], 90: []}
    for f in findings:
        p = phase_of(f)
        if p is not None:
            out[p].append(f)
    return out


def projected_overall(findings, assessed, fixed_ids=(), caps=None):
    """Average domain score over the assessed domains once fixed_ids are resolved.

    A detection capability that scores under 100 keeps that score as a ceiling until one of the findings that
    fix it (capabilities.FIXERS) is resolved, because its score comes from what the tenant can see and not
    only from the findings.
    """
    fixed = set(fixed_ids)
    if not assessed:
        return None
    ceil = ceilings(caps) if caps else {}
    total = 0
    for dom in assessed:
        penalty = sum(SEVERITY_PENALTY[f["severity"]] for f in findings
                      if f["domain"] == dom and f["id"] not in fixed)
        score_now = max(0, 100 - penalty)
        if dom in ceil and not (set(ceil[dom][1]) & fixed):
            score_now = min(score_now, ceil[dom][0])
        total += score_now
    return round(total / len(assessed))


def projections(findings, assessed, caps=None):
    """Overall score now and after each phase, cumulative."""
    p = plan(findings)
    fixed, rows = [], [("Today", projected_overall(findings, assessed, caps=caps))]
    for days in PHASES:
        fixed += [f["id"] for f in p[days]]
        rows.append((f"After {days} days", projected_overall(findings, assessed, fixed, caps)))
    return rows
