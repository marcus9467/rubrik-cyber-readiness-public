"""Edition entitlement per finding id, with provenance.

`tag` in score.py says what kind of fix a finding needs. This file says which license the capability behind
the fix needs. They are separate because "needs Enterprise" and "nobody has confirmed what it needs" are
different claims, and only the first can go in an upgrade conversation.

Each entry:
  status     any | enterprise   (what the capability is believed to require)
  source     where that belief comes from (doc URL, price book line, or who confirmed it and when)
  confirmed  True only after someone checked the source against the price book or product management

A finding is shown as needing Enterprise only when status is enterprise AND confirmed is True. Anything
else, including every rule id not listed here, is bucketed "unconfirmed" and the report states no edition.
tests/test_editions.py enforces that confirmed entries carry a source.
"""

ANY, ENTERPRISE, UNCONFIRMED = "any", "enterprise", "unconfirmed"

EDITIONS = {
    # Only entitlement on record: a docs.rubrik.com search snippet calling threat monitoring an Enterprise
    # feature. A snippet is not a price book line, so confirmed stays False until someone checks.
    "T-1": {
        "status": ENTERPRISE,
        "confirmed": False,
        "source": "docs.rubrik.com search snippet describing threat monitoring as Enterprise (2026-10-09).",
    },
}


def edition_of(rule_id):
    """Entitlement for a rule id. Unlisted ids and unconfirmed entries both report status unconfirmed."""
    e = EDITIONS.get(rule_id)
    if not e or not e.get("confirmed") or not e.get("source", "").strip():
        return {"status": UNCONFIRMED, "believed": e["status"] if e else None,
                "source": e.get("source", "") if e else "", "confirmed": False}
    return {"status": e["status"], "believed": e["status"], "source": e["source"], "confirmed": True}


def bucket(tag, rule_id):
    """Report bucket: fix_now | process | visibility | enterprise | unconfirmed.

    A confirmed-Enterprise finding goes to `enterprise` whatever its tag. A fix_now or process finding that is
    not edition-gated keeps its tag. An ee_candidate with no confirmed entitlement is `unconfirmed`.
    """
    ed = edition_of(rule_id)
    if ed["status"] == ENTERPRISE:
        return "enterprise"
    if tag in ("fix_now", "process", "visibility"):
        return tag
    return "unconfirmed"
