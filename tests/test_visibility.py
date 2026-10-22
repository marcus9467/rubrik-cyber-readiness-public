"""Visibility rules V-1 to V-4: a capability the tenant cannot see is a critical finding and a zero score."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from score import score  # noqa: E402
from posture import domain_rows  # noqa: E402
from roadmap import projections  # noqa: E402
from test_score import hardened, ids  # noqa: E402
from test_delta import ALL_OK  # noqa: E402


def bundle():
    b = hardened()
    b["status"] = dict(ALL_OK)
    return b


def find(b, rid):
    return next((f for f in score(b)["findings"] if f["id"] == rid), None)


def test_clean_tenant_has_no_visibility_findings():
    assert not {"V-1", "V-2", "V-3", "V-4"} & ids(bundle())


def test_dark_capability_is_critical_and_scores_zero():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")
    f = find(b, "V-4")
    assert f["severity"] == "critical" and f["bucket"] == "visibility" and f["domain"] == "Sensitive Data Discovery"
    assert "exposure cannot be sized" in f["evidence"]
    r = score(b)
    assert r["domain_scores"]["Sensitive Data Discovery"] == 0


def test_failed_collector_is_a_zero_not_a_grey_blank():
    b = bundle()
    b["status"]["threat"] = "error: denied"
    r = score(b)
    assert r["domain_scores"]["Threat Monitoring"] == 0
    rows = dict(domain_rows(r, b["data"]))
    assert rows["Threat Monitoring"] == 0, "must be 0, never None"
    assert find(b, "V-2")["severity"] == "critical"


def test_every_blind_path_says_why():
    from capabilities import NOT_REPORTED, NOTHING_LISTED
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")
    assert score(b)["capabilities"]["Sensitive Data Discovery"]["reason"] == NOT_REPORTED
    b = bundle()
    b["status"]["dhrc"] = "error: denied"
    assert "cluster health query failed" in score(b)["capabilities"]["Anomaly Detection"]["reason"]
    b = bundle()
    b["status"]["threat"] = "error: denied"
    assert "threat monitoring query failed" in score(b)["capabilities"]["Threat Monitoring"]["reason"]
    b = bundle()
    b["data"]["threat"] = {"roots": {}, "objects": None}
    assert score(b)["capabilities"]["Threat Monitoring"]["reason"] == NOTHING_LISTED


def test_reason_is_empty_unless_blind_and_never_quotes_the_api():
    b = bundle()
    b["data"]["threat"] = {"roots": {}, "objects": None}
    b["status"]["dhrc"] = "error: HTTP 403 host vcenter.acme.example denied"
    caps = score(b)["capabilities"]
    assert "acme" not in caps["Anomaly Detection"]["reason"]
    assert all(c["reason"] == "" for c in caps.values() if c["state"] != "blind")


def test_hunt_failure_does_not_grey_out_alerting_or_add_a_hunting_row():
    b = bundle()
    b["data"]["detection"]["hunts"] = {"error": "denied"}
    rows = dict(domain_rows(score(b), b["data"]))
    assert "Threat Hunting" not in rows
    assert rows["Alerting"] is not None, "Alerting depends on settings and webhooks, not on hunt history"


def test_alerting_is_still_not_assessed_when_its_own_queries_fail():
    b = bundle()
    b["data"]["detection"]["webhooks"] = {"error": "denied"}
    assert dict(domain_rows(score(b), b["data"]))["Alerting"] is None


def test_never_hunted_is_not_a_finding_and_does_not_move_the_score():
    b = bundle()
    base = score(b)
    b["data"]["detection"]["hunts"] = {"total": 0, "last90": 0, "latest": None}
    r = score(b)
    assert "V-3" not in {f["id"] for f in r["findings"]}
    assert r["domain_scores"] == base["domain_scores"] and r["counts"] == base["counts"]
    assert r["hunt_note"] == "No threat hunt has been run on this tenant."


def test_partial_coverage_is_high_or_medium_never_critical():
    b = bundle()
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0].update(value=1, maxValue=4)
    assert find(b, "V-1")["severity"] == "high"
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0].update(value=8, maxValue=9)
    assert find(b, "V-1")["severity"] == "medium"


def test_old_bundle_without_hunt_history_is_not_called_blind():
    b = bundle()
    del b["data"]["detection"]["hunts"]
    assert "V-3" not in ids(b)
    assert score(b)["hunt_note"] is None


def test_t1_is_not_reported_twice():
    b = bundle()
    b["data"]["threat"]["roots"] = {"AWS_NATIVE_ACCOUNT": {"total": 4, "threatMonitoringEnabled": 1}}
    got = ids(b)
    assert "T-1" in got and "V-2" not in got


def test_projection_keeps_the_capability_ceiling_until_it_is_fixed():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")
    r = score(b)
    assessed = [d for d, v in domain_rows(r, b["data"]) if v is not None]
    rows = dict(projections(r["findings"], assessed, r["capabilities"]))
    assert rows["Today"] < rows["After 30 days"], "V-4 is a 30 day item, so fixing it lifts the score"
    no_caps = dict(projections(r["findings"], assessed))
    assert no_caps["After 30 days"] >= rows["After 30 days"]


def test_t2_exposure_is_not_labelled_a_visibility_gap():
    b = bundle()
    b["data"]["dhrc"]["scores"]["SENSITIVE_DATA"]["metrics"][1].update(value=500, maxValue=1000)
    assert find(b, "T-2")["bucket"] == "process"


def test_visibility_findings_name_the_edition_that_closes_the_gap():
    b = bundle()
    for k in ("threat", "dhrc"):
        b["status"][k] = "error: denied"
    got = {f["id"]: f["edition"]["edition"] for f in score(b)["findings"] if f["id"].startswith("V-")}
    assert got == {"V-1": "Business", "V-2": "Enterprise", "V-4": "Enterprise"}
