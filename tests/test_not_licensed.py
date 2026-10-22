import copy
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import brand  # noqa: E402
import render_html  # noqa: E402
from score import score  # noqa: E402
from test_score import hardened  # noqa: E402


def ids(result):
    return {f["id"] for f in result["findings"]}


def with_threat_gap():
    b = copy.deepcopy(hardened())
    b["data"]["threat"] = {"roots": {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 1}}}
    return b


def test_threat_gap_fires_by_default_and_is_dropped_when_not_licensed():
    b = with_threat_gap()
    assert "T-1" in ids(score(b))
    r = score(b, ["Threat Monitoring"])
    assert not ({"T-1", "V-2"} & ids(r))
    assert "Threat Monitoring" not in r["capabilities"] and "Threat Monitoring" not in r["domain_scores"]
    assert r["not_licensed"] == ["Threat Monitoring"]


def test_not_licensed_leaves_other_capabilities_and_ignores_unknown_names():
    r = score(with_threat_gap(), ["Threat Monitoring", "Not A Capability"])
    assert {"Anomaly Detection", "Sensitive Data Discovery"} <= set(r["capabilities"])
    assert r["not_licensed"] == ["Threat Monitoring"]
    assert score(hardened())["not_licensed"] == []


def test_brand_json_not_licensed_is_read_and_bad_values_ignored():
    d = Path(tempfile.mkdtemp())
    os.environ["CRR_BRAND_DIR"] = str(d)
    try:
        (d / "brand.json").write_text(json.dumps({"not_licensed": ["Threat Monitoring", 5, None]}))
        assert brand.load()["not_licensed"] == ["Threat Monitoring"]
        (d / "brand.json").write_text(json.dumps({"not_licensed": "Threat Monitoring"}))
        assert brand.load()["not_licensed"] == []
    finally:
        os.environ.pop("CRR_BRAND_DIR", None)


def test_report_html_omits_excluded_capability_and_never_calls_it_a_failure():
    d = Path(tempfile.mkdtemp())
    (d / "brand.json").write_text(json.dumps({"not_licensed": ["Threat Monitoring"]}))
    os.environ["CRR_BRAND_DIR"] = str(d)
    try:
        html, result = render_html.build_html(with_threat_gap())
    finally:
        os.environ.pop("CRR_BRAND_DIR", None)
    assert "not part of this licence" in html
    # The failure callout lists areas whose collector did not run. Threat Monitoring must never be among them.
    import re
    m = re.search(r"<b>Not assessed:</b>([^<]*)", html)
    assert m is None or "Threat Monitoring" not in m.group(1)
    assert "T-1" not in {f["id"] for f in result["findings"]}


def offsite_bundle(relic, archived):
    b = copy.deepcopy(hardened())
    b["data"]["offsite"].update({"objects": 100, "objectsReplicationKnown": 100, "noReplication": 90})
    b["data"]["inventory"]["reconciliation"] = {"snappables": {"activeProtected": 40, "relic": relic,
                                                               "archived": archived}}
    return b


def test_offsite_finding_says_relics_are_counted_when_there_are_any():
    f = next(x for x in score(offsite_bundle(50, 10))["findings"] if x["id"] == "RP-1")
    assert "relic and archived" in f["evidence"] and "40 active protected" in f["evidence"]
    assert "60 relic or archived" in f["evidence"]


def test_offsite_finding_has_no_relic_note_without_relics_or_inventory():
    f = next(x for x in score(offsite_bundle(0, 0))["findings"] if x["id"] == "RP-1")
    assert "relic" not in f["evidence"]
    b = offsite_bundle(50, 10)
    del b["data"]["inventory"]["reconciliation"]
    f = next(x for x in score(b)["findings"] if x["id"] == "RP-1")
    assert "relic" not in f["evidence"]
