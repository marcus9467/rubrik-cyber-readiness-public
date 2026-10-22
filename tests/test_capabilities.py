"""Capability model: a capability Rubrik cannot show scores 0, never "not assessed"."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capabilities import ceilings, compute  # noqa: E402

OK = {"dhrc": "ok", "threat": "ok", "detection": "ok"}


def data(ad=(9, 9), sdd=(9, 9), roots=None, objects=None, hunts=None, **extra):
    d = {
        "dhrc": {"scores": {
            "ANOMALIES_DETECTED": {"metrics": [{"metric": "RADAR_ENABLED_CLUSTERS", "value": ad[0], "maxValue": ad[1]}]},
            "SENSITIVE_DATA": {"metrics": [{"metric": "DATA_DISCOVERY_ENABLED_CLUSTERS", "value": sdd[0],
                                            "maxValue": sdd[1]}]}}},
        "threat": {"roots": roots if roots is not None else {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 2}},
                   "objects": objects},
        "detection": {"settings": {}, "hunts": hunts if hunts is not None else
                      {"total": 5, "last90": 2, "latest": "2026-10-01T00:00:00Z"}},
    }
    d.update(extra)
    return d


def test_healthy_tenant_is_active_everywhere():
    caps = compute(data(), OK)
    assert [c["state"] for c in caps.values()] == ["active"] * 4
    assert [c["score"] for c in caps.values()] == [100] * 4
    assert ceilings(caps) == {}


def test_blind_capability_scores_zero_not_none():
    d = data()
    del d["threat"]
    caps = compute(d, {**OK, "threat": "error: denied"})
    assert caps["Threat Monitoring"]["state"] == "blind" and caps["Threat Monitoring"]["score"] == 0


def test_dhrc_failure_blinds_both_anomaly_and_sensitive_data():
    caps = compute({"detection": data()["detection"], "threat": data()["threat"]}, {**OK, "dhrc": "error: x"})
    assert caps["Anomaly Detection"]["score"] == 0 and caps["Sensitive Data Discovery"]["score"] == 0
    assert caps["Threat Hunting"]["state"] == "active"


def test_missing_metric_is_blind_and_zero_coverage_is_off():
    d = data()
    d["dhrc"]["scores"].pop("SENSITIVE_DATA")
    assert compute(d, OK)["Sensitive Data Discovery"]["state"] == "blind"
    assert compute(data(ad=(0, 9)), OK)["Anomaly Detection"]["state"] == "off"
    assert compute(data(ad=(0, 9)), OK)["Anomaly Detection"]["score"] == 0


def test_partial_scores_the_coverage_and_is_never_100_or_0():
    c = compute(data(ad=(8, 9)), OK)["Anomaly Detection"]
    assert c["state"] == "partial" and c["score"] == 89
    assert 1 <= compute(data(ad=(1, 1000)), OK)["Anomaly Detection"]["score"] <= 99
    assert compute(data(ad=(999, 1000)), OK)["Anomaly Detection"]["score"] == 99


def test_old_bundle_without_the_collector_is_not_collected_not_blind():
    caps = compute({}, {})
    assert all(c["state"] == "not_collected" and c["score"] is None for c in caps.values())
    old_detection = {"detection": {"settings": {}}, "dhrc": data()["dhrc"], "threat": data()["threat"]}
    c = compute(old_detection, OK)["Threat Hunting"]
    assert c["state"] == "not_collected", "a detection section with no hunts key predates hunt history"


def test_present_data_with_no_status_entry_counts_as_collected():
    assert compute(data(), {})["Anomaly Detection"]["state"] == "active"


def test_threat_hunting_states():
    assert compute(data(), OK)["Threat Hunting"]["score"] == 100
    lapsed = compute(data(hunts={"total": 4, "last90": 0, "latest": "2026-01-01T00:00:00Z"}), OK)["Threat Hunting"]
    assert lapsed["state"] == "partial" and lapsed["score"] == 50
    never = compute(data(hunts={"total": 0, "last90": 0, "latest": None}), OK)["Threat Hunting"]
    assert never["state"] == "off" and never["score"] == 0 and "ever been run" in never["evidence"]
    stub = compute(data(hunts={"error": "denied"}), OK)["Threat Hunting"]
    assert stub["state"] == "blind" and stub["score"] == 0


def test_threat_monitoring_scores_clusters_and_accounts_and_ignores_object_stats():
    roots = {"AWS_NATIVE_ACCOUNT": {"total": 4, "threatMonitoringEnabled": 2},
             "CDM_CLUSTER": {"total": 4, "threatMonitoringEnabled": 2}}
    c = compute(data(roots=roots, objects={"enabledObjects": 3018, "supportedObjects": 2808}), OK)["Threat Monitoring"]
    assert c["state"] == "partial" and c["score"] == 50  # 4 of 8 roots; the object stats do not move it
    assert "2 of 4 Rubrik clusters; 2 of 4 cloud and SaaS accounts" in c["evidence"]
    assert "workload objects" not in c["evidence"]


def test_partial_state_gets_its_own_consequence_and_off_keeps_the_full_one():
    from capabilities import CONSEQUENCE, consequence
    for dom in CONSEQUENCE:
        assert consequence(dom, "partial") != consequence(dom, "off")
        assert consequence(dom, "off") == consequence(dom, "blind") == CONSEQUENCE[dom]
    assert "outside the covered" in consequence("Threat Monitoring", "partial")


def test_threat_monitoring_counts_cdm_clusters_and_leaves_out_unreadable_ones():
    roots = {"CDM_CLUSTER": {"total": 8, "threatMonitoringEnabled": 8, "notAssessed": [{"id": "x", "name": "x"}]}}
    c = compute(data(roots=roots, objects=None), OK)["Threat Monitoring"]
    assert c["state"] == "active" and c["score"] == 100  # the disconnected cluster is neither credited nor counted off


def test_threat_monitoring_with_nothing_reporting_is_blind():
    c = compute(data(roots={"AWS_NATIVE_ACCOUNT": {"error": "x"}, "CDM_CLUSTER": {"total": 0}}), OK)["Threat Monitoring"]
    assert c["state"] == "blind" and c["score"] == 0


def test_threat_monitoring_fully_off_is_off():
    c = compute(data(roots={"AWS_NATIVE_ACCOUNT": {"total": 3, "threatMonitoringEnabled": 0}}), OK)["Threat Monitoring"]
    assert c["state"] == "off" and c["score"] == 0


def test_ceilings_name_the_findings_that_lift_them():
    caps = compute(data(ad=(0, 9), roots={"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 1}}), OK)
    c = ceilings(caps)
    assert c["Anomaly Detection"] == (0, ("V-1",))
    assert c["Threat Monitoring"] == (50, ("V-2", "T-1"))
    assert "Threat Hunting" not in c
