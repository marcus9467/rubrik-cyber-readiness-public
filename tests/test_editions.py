"""Edition is a label. It never changes a score, a phase or a bucket."""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import capabilities  # noqa: E402
from editions import CAPABILITY_EDITION, RULE_CAPABILITY, bucket, edition_of  # noqa: E402
from render_html import build_html  # noqa: E402
from roadmap import phase_of, projections  # noqa: E402
from score import score  # noqa: E402
from test_delta import ALL_OK  # noqa: E402
from test_score import hardened  # noqa: E402


def test_each_capability_names_the_edition_that_includes_it():
    assert CAPABILITY_EDITION == {"Anomaly Detection": "Business", "Threat Monitoring": "Enterprise",
                                  "Threat Hunting": "Enterprise", "Sensitive Data Discovery": "Enterprise"}


def test_every_scored_capability_has_an_edition():
    assert set(capabilities.DOMAINS) <= set(CAPABILITY_EDITION)


def test_findings_resolve_to_their_capability_and_unrelated_rules_have_no_edition():
    assert edition_of("T-1") == {"edition": "Enterprise", "capability": "Threat Monitoring"}
    assert edition_of("V-1") == {"edition": "Business", "capability": "Anomaly Detection"}
    assert edition_of("T-2") == {"edition": "Enterprise", "capability": "Sensitive Data Discovery"}
    assert edition_of("ID-1") == {"edition": None, "capability": None}
    assert set(RULE_CAPABILITY.values()) <= set(CAPABILITY_EDITION)


def test_edition_never_moves_a_finding_between_buckets():
    for tag in ("fix_now", "process", "visibility"):
        for rid in ("T-1", "V-4", "ID-1"):
            assert bucket(tag, rid) == tag


def test_an_enterprise_gated_finding_is_dated_like_any_other():
    f = {"id": "T-1", "severity": "high", "bucket": "visibility", "edition": edition_of("T-1")}
    assert phase_of(f) == 30
    assert phase_of({**f, "severity": "medium"}) == 60


def test_an_enterprise_gap_is_assumed_fixed_in_the_projection():
    fs = [{"id": "T-1", "domain": "Threat Monitoring", "severity": "high", "bucket": "visibility",
           "edition": edition_of("T-1")}]
    rows = dict(projections(fs, ["Threat Monitoring"]))
    assert rows["Today"] == 85 and rows["After 30 days"] == 100


def test_the_score_is_the_same_whatever_the_finding_edition():
    b = copy.deepcopy(hardened())
    b["data"]["threat"] = {"roots": {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 1}}}
    r = score(b)
    t1 = next(f for f in r["findings"] if f["id"] == "T-1")
    assert t1["edition"]["edition"] == "Enterprise"
    stripped = copy.deepcopy(r["findings"])
    for f in stripped:
        f["edition"] = {"edition": None, "capability": None}
    assert [f["severity"] for f in stripped] == [f["severity"] for f in r["findings"]]
    assert r["domain_scores"]["Threat Monitoring"] == 50


def test_the_report_names_the_edition_on_cards_and_findings():
    b = copy.deepcopy(hardened())
    b["status"] = dict(ALL_OK)
    b["data"]["threat"] = {"roots": {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 1}}}
    html, _ = build_html(b)
    assert "Included in Enterprise Edition and above." in html
    assert "Included in Business Edition and above." in html
    assert "Threat Monitoring is included in Enterprise Edition and above." in html
    assert "Threat hunting is an on-demand action, included in Enterprise Edition and above." in html
    assert "Edition unconfirmed" not in html and "Decide after licensing" not in html
