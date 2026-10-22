"""Rerun delta: progress is only claimed where both runs could actually see the data."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from delta import changed_numbers, compute, describe_change  # noqa: E402
from test_score import hardened  # noqa: E402

ALL_OK = {k: "ok" for k in ("identity", "mfa", "quorum", "inventory", "dhrc", "sla", "access", "clusters",
                            "threat", "detection", "recovery", "offsite")}


def bundle(**changes):
    b = copy.deepcopy(hardened())
    b["status"] = dict(ALL_OK)
    for path, val in changes.items():
        section, key = path.split("__")
        b["data"][section][key] = val
    return b


def test_identical_runs_show_no_change():
    d = compute(bundle(), bundle())
    assert not d["resolved"] and not d["new"] and not d["worse"] and not d["improved"] and not d["moved"]
    assert d["overall"]["before"] == d["overall"]["after"]


def test_fixed_finding_is_resolved_and_new_one_is_new():
    before = bundle(mfa__isTotpEnforcedGlobal=False)
    after = bundle(clusters__encryptionOff=1)
    d = compute(before, after)
    assert [f["id"] for f in d["resolved"]] == ["MFA-1"]
    assert [f["id"] for f in d["new"]] == ["CL-1"]


def test_failed_collector_is_not_reported_as_resolved():
    before = bundle(mfa__isTotpEnforcedGlobal=False)
    after = bundle()
    after["status"]["mfa"] = "error: denied"
    d = compute(before, after)
    assert "MFA" in d["not_comparable"]
    assert not d["resolved"], "a finding hidden by a failed collector is not progress"


def test_sub_query_error_stub_is_not_reported_as_resolved():
    before = bundle(detection__settings={"isAnomalyAlertEnabled": False})
    after = bundle(detection__settings={"error": "denied"})
    d = compute(before, after)
    assert "Alerting" in d["not_comparable"]
    assert "T-3" not in [f["id"] for f in d["resolved"]]


def test_overall_is_like_for_like():
    before = bundle(clusters__encryptionOff=1)
    after = bundle()
    after["status"]["recovery"] = "error: denied"
    d = compute(before, after)
    assert "Recovery" in d["not_comparable"]
    assert d["overall"]["after"] > d["overall"]["before"]
    assert set(d["domains"]) == {"Identity", "MFA", "Quorum", "Access", "RBAC", "Immutability", "Coverage",
                                 "Platform", "Anomaly Detection", "Threat Monitoring", "Threat Hunting",
                                 "Sensitive Data Discovery", "Alerting"}


def test_severity_change_is_improved_or_worse():
    # RC-2 is medium below 50 percent never-run and high at or above it.
    low = bundle(recovery__total=4, recovery__neverRun=1)
    high = bundle(recovery__total=4, recovery__neverRun=3)
    d = compute(high, low)
    assert [(x["id"], x["severity"], y["severity"]) for x, y in d["improved"]] == [("RC-2", "high", "medium")]
    assert not d["worse"] and not d["resolved"] and not d["new"]
    d = compute(low, high)
    assert [(x["id"], x["severity"], y["severity"]) for x, y in d["worse"]] == [("RC-2", "medium", "high")]
    assert not d["improved"]


def test_changed_numbers():
    assert changed_numbers("9 of 55 users", "9 of 56 users") == [("55", "56")]
    assert changed_numbers("a 1 b", "a 1 b") == []
    assert changed_numbers("1 of 2", "1 of 2 and 3")[0][0] == "text changed"


def test_describe_change_names_the_finding_and_caps_pairs():
    x = {"title": "T", "evidence": "1 2 3 4 5"}
    y = {"title": "T", "evidence": "9 8 7 6 5"}
    out = describe_change(x, y)
    assert out.startswith("T: 1 to 9, 2 to 8, 3 to 7") and out.endswith("(+1 more)")
