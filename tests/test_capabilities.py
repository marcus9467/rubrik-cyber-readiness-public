"""Capability model: a capability Rubrik cannot show scores 0, never "not assessed"."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capabilities import ceilings, compute, hunt_note, summary  # noqa: E402

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
    assert list(caps) == ["Anomaly Detection", "Threat Monitoring", "Sensitive Data Discovery"]
    assert [c["state"] for c in caps.values()] == ["active"] * 3
    assert [c["score"] for c in caps.values()] == [100] * 3
    assert ceilings(caps) == {}


def test_blind_capability_scores_zero_not_none():
    d = data()
    del d["threat"]
    caps = compute(d, {**OK, "threat": "error: denied"})
    assert caps["Threat Monitoring"]["state"] == "blind" and caps["Threat Monitoring"]["score"] == 0


def test_dhrc_failure_blinds_both_anomaly_and_sensitive_data():
    caps = compute({"detection": data()["detection"], "threat": data()["threat"]}, {**OK, "dhrc": "error: x"})
    assert caps["Anomaly Detection"]["score"] == 0 and caps["Sensitive Data Discovery"]["score"] == 0
    assert caps["Threat Monitoring"]["state"] == "active"


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


def test_score_with_no_cluster_metrics_is_unverified_not_blind_and_not_scored():
    # RSC returned the bucket score but withheld every per-cluster metric (seen on a live tenant). The bucket reports
    # detections, not enablement, so it must not be read as "on" and must not be scored 0 either.
    d = data()
    d["dhrc"]["scores"]["ANOMALIES_DETECTED"] = {"value": 100, "metrics": []}
    d["dhrc"]["scores"]["SENSITIVE_DATA"] = {"value": 100, "metrics": []}
    caps = compute(d, OK)
    for dom in ("Anomaly Detection", "Sensitive Data Discovery"):
        assert caps[dom]["state"] == "unverified" and caps[dom]["score"] is None
        assert caps[dom]["reason"]
    assert ceilings(caps) == {}


def test_bucket_missing_entirely_is_still_blind():
    d = data()
    d["dhrc"]["scores"].pop("ANOMALIES_DETECTED")
    assert compute(d, OK)["Anomaly Detection"]["state"] == "blind"


def test_not_licensed_scores_zero_and_counts_and_wins_over_the_data():
    caps = compute(data(sdd=(9, 9)), OK, not_licensed=["Sensitive Data Discovery"])
    c = caps["Sensitive Data Discovery"]
    assert c["state"] == "not_licensed" and c["score"] == 0
    assert caps["Anomaly Detection"]["state"] == "active"
    assert "Sensitive Data Discovery" in summary(caps)["not_licensed"]


def test_confirmed_active_scores_100_and_says_it_is_the_assessor():
    d = data()
    d["dhrc"]["scores"]["ANOMALIES_DETECTED"] = {"value": 100, "metrics": []}
    c = compute(d, OK, confirmed_active=["Anomaly Detection"])["Anomaly Detection"]
    assert c["state"] == "active" and c["score"] == 100 and c["source"] == "assessor"
    assert "Confirmed" in c["evidence"]


def test_assessor_flags_default_to_the_data_keys_so_rules_agree_with_the_report():
    d = data(sdd=(0, 9))
    d["_not_licensed"] = ("Sensitive Data Discovery",)
    d["_confirmed_active"] = ("Anomaly Detection",)
    caps = compute(d, OK)
    assert caps["Sensitive Data Discovery"]["state"] == "not_licensed"
    assert caps["Anomaly Detection"]["source"] == "assessor"


def test_old_bundle_without_the_collector_is_not_collected_not_blind():
    caps = compute({}, {})
    assert all(c["state"] == "not_collected" and c["score"] is None for c in caps.values())


def test_present_data_with_no_status_entry_counts_as_collected():
    assert compute(data(), {})["Anomaly Detection"]["state"] == "active"


def test_hunting_is_not_a_scored_capability():
    caps = compute(data(hunts={"total": 0, "last90": 0, "latest": None}), OK)
    assert "Threat Hunting" not in caps
    assert compute(data(hunts={"error": "denied"}), OK) == compute(data(), OK)


def test_hunt_note_reports_history_and_never_says_gap():
    assert hunt_note(data(), OK) == "5 threat hunts have been run on this tenant; the most recent started on 2026-10-01."
    assert hunt_note(data(hunts={"total": 1, "last90": 0, "latest": "2026-01-01T00:00:00Z"}), OK).startswith(
        "1 threat hunt has been run")
    assert hunt_note(data(hunts={"total": 0, "last90": 0, "latest": None}), OK) == \
        "No threat hunt has been run on this tenant."


def test_hunt_note_with_hunts_but_no_start_time_does_not_print_an_empty_date():
    note = hunt_note(data(hunts={"total": 2, "last90": 0, "latest": None}), OK)
    assert note == "2 threat hunts have been run on this tenant." and "started on" not in note


def test_hunt_note_is_silent_when_it_cannot_be_sure():
    assert hunt_note(data(hunts={"error": "denied"}), OK) is None            # query failed
    d = data()
    del d["detection"]["hunts"]
    assert hunt_note(d, OK) is None                                          # bundle predates hunt history
    assert hunt_note(data(), {**OK, "detection": "error: x"}) is None        # collector failed
    assert hunt_note({}, {}) is None


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


def _no_ad_metric(**det):
    """Live-tenant shape: the cluster health score came back with no per-cluster Anomaly Detection metric."""
    d = data(detection={"settings": {}, "hunts": {"total": 0, "last90": 0, "latest": None}, **det})
    d["dhrc"]["scores"].pop("ANOMALIES_DETECTED")
    return d


def _re(*pairs):
    return {"ransomwareEnablement": {"roots": {k: {"total": t, "enabled": e} for k, t, e in pairs}}}


def test_anomaly_falls_back_to_account_enablement_when_the_cluster_metric_is_missing():
    d = _no_ad_metric(**_re(("awsAccounts", 4, 2)))
    d["threat"]["roots"].pop("CDM_CLUSTER", None)
    c = compute(d, OK)["Anomaly Detection"]
    assert c["state"] == "partial" and c["score"] == 50 and c["source"] == "enablement"


def test_anomaly_full_cloud_coverage_is_active_only_when_there_are_no_rubrik_clusters():
    d = _no_ad_metric(**_re(("awsAccounts", 2, 2), ("microsoft365Subscriptions", 1, 1)))
    d["threat"]["roots"].pop("CDM_CLUSTER", None)
    assert compute(d, OK)["Anomaly Detection"]["state"] == "active"


def test_anomaly_full_cloud_coverage_with_rubrik_clusters_is_unverified_not_active():
    d = _no_ad_metric(**_re(("awsAccounts", 2, 2)))
    d["threat"]["roots"]["CDM_CLUSTER"] = {"total": 3, "threatMonitoringEnabled": 3, "notAssessed": []}
    c = compute(d, OK)["Anomaly Detection"]
    assert c["state"] == "unverified" and c["score"] is None


def test_anomaly_with_no_enablement_data_keeps_the_original_reading():
    d = _no_ad_metric()
    assert compute(d, OK)["Anomaly Detection"]["state"] == "blind"
    d = _no_ad_metric(ransomwareEnablement={"error": "denied"})
    assert compute(d, OK)["Anomaly Detection"]["state"] == "blind"


def test_cluster_metric_wins_over_enablement_when_present():
    d = data(ad=(0, 9), detection={"settings": {}, "hunts": {}, **_re(("awsAccounts", 2, 2))})
    assert compute(d, OK)["Anomaly Detection"]["state"] == "off"


def test_sensitive_data_positive_count_lifts_a_blind_reading():
    d = data(detection={"settings": {}, "hunts": {}, "dataDiscovery": {"assigned": 30, "notAssigned": 10}})
    d["dhrc"]["scores"].pop("SENSITIVE_DATA")
    c = compute(d, OK)["Sensitive Data Discovery"]
    assert c["state"] == "partial" and c["score"] == 75 and c["source"] == "enablement"


def test_sensitive_data_zero_policies_is_off_not_blind_and_never_a_license_claim():
    d = data(detection={"settings": {}, "hunts": {}, "dataDiscovery": {"assigned": 0, "notAssigned": 40}})
    d["dhrc"]["scores"].pop("SENSITIVE_DATA")
    c = compute(d, OK)["Sensitive Data Discovery"]
    assert c["state"] == "off" and c["score"] == 0 and c["state"] != "not_licensed"
    assert "No Data Discovery policy" in c["evidence"]


def test_sensitive_data_with_no_objects_at_all_stays_blind():
    d = data(detection={"settings": {}, "hunts": {}, "dataDiscovery": {"assigned": 0, "notAssigned": 0}})
    d["dhrc"]["scores"].pop("SENSITIVE_DATA")
    assert compute(d, OK)["Sensitive Data Discovery"]["state"] == "blind"


def _scan(with_=5, resolved=1, without=24, unscanned=70):
    return {"anomalyScan": {"enabled": with_ + resolved + without + unscanned, "withAnomalies": with_,
                            "resolved": resolved, "withoutAnomalies": without, "unscanned": unscanned}}


def test_anomaly_scan_share_is_the_primary_and_beats_a_cluster_setting_that_says_on():
    d = data(ad=(9, 9), detection={"settings": {}, "hunts": {}, **_scan()})
    c = compute(d, OK)["Anomaly Detection"]
    assert c["state"] == "partial" and c["score"] == 30 and c["source"] == "scan"
    assert "30 of 100" in c["evidence"]


def test_anomaly_scan_counts_resolved_objects_as_scanned():
    c = compute(data(detection={"settings": {}, "hunts": {}, **_scan(0, 10, 0, 0)}), OK)["Anomaly Detection"]
    assert c["state"] == "active" and c["score"] == 100


def test_anomaly_nothing_scanned_is_off_and_never_not_licensed():
    c = compute(data(detection={"settings": {}, "hunts": {}, **_scan(0, 0, 0, 50)}), OK)["Anomaly Detection"]
    assert c["state"] == "off" and c["score"] == 0


def test_anomaly_scan_error_stub_or_empty_universe_falls_back_to_the_older_signals():
    for bad in ({"error": "denied"}, _scan(0, 0, 0, 0)["anomalyScan"]):
        d = data(ad=(0, 9), detection={"settings": {}, "hunts": {}, "anomalyScan": bad})
        assert compute(d, OK)["Anomaly Detection"]["state"] == "off"


def test_threat_monitoring_scan_is_only_a_fallback_when_no_root_could_be_read():
    scan = {"withThreats": 2, "withoutThreats": 38, "unscanned": 60}
    d = data(roots={})
    d["threat"]["scan"] = scan
    c = compute(d, OK)["Threat Monitoring"]
    assert c["state"] == "partial" and c["score"] == 40 and c["source"] == "scan"
    d = data()  # a readable root wins, the scan does not override it
    d["threat"]["scan"] = scan
    c = compute(d, OK)["Threat Monitoring"]
    assert c["state"] == "active" and c.get("source") != "scan"


def test_threat_monitoring_scan_share_is_evidence_and_never_changes_the_per_root_score():
    d = data()
    d["threat"]["scan"] = {"withThreats": 2, "withoutThreats": 38, "unscanned": 60}
    c = compute(d, OK)["Threat Monitoring"]
    assert c["state"] == "active" and c["score"] == 100
    assert "scanned 40 of 100 objects (40%)" in c["evidence"]
    d["threat"]["scan"] = {"error": "denied"}
    assert "scanned" not in compute(d, OK)["Threat Monitoring"]["evidence"]


def _dd(assigned=2376, not_assigned=1548):
    return {"detection": {"settings": {}, "hunts": {}, "dataDiscovery": {"assigned": assigned, "notAssigned": not_assigned}}}


def test_sensitive_data_policy_coverage_is_evidence_and_never_changes_the_cluster_score():
    d = data(sdd=(6, 8), **_dd())
    c = compute(d, OK)["Sensitive Data Discovery"]
    assert c["state"] == "partial" and c["score"] == 75
    assert c["evidence"].count("policies are assigned") == 1
    assert "on for 6 of 8 clusters" in c["evidence"]
    assert "assigned to 2,376 of 3,924 supported objects (61%)" in c["evidence"]


def test_sensitive_data_policy_coverage_is_left_out_when_unreadable_or_empty():
    for dd in ({"error": "denied"}, {"assigned": 0, "notAssigned": 0}):
        d = data(sdd=(6, 8), detection={"settings": {}, "hunts": {}, "dataDiscovery": dd})
        c = compute(d, OK)["Sensitive Data Discovery"]
        assert c["score"] == 75 and "policies" not in c["evidence"]
    assert "policies" not in compute(data(sdd=(6, 8)), OK)["Sensitive Data Discovery"]["evidence"]


def test_sensitive_data_fallback_reading_does_not_repeat_the_policy_line():
    d = data(**_dd(30, 10))
    d["dhrc"]["scores"].pop("SENSITIVE_DATA")
    c = compute(d, OK)["Sensitive Data Discovery"]
    assert c["evidence"].count("policies are assigned") == 1


def test_scan_based_partial_consequence_talks_about_objects_not_clusters():
    from capabilities import consequence
    for dom in ("Anomaly Detection", "Threat Monitoring", "Sensitive Data Discovery"):
        scan = consequence(dom, "partial", "scan")
        assert "cluster" not in scan.lower() and "object" in scan.lower()
        assert consequence(dom, "partial") != scan  # a cluster-setting reading keeps its cluster wording
        assert consequence(dom, "off", "scan") == consequence(dom, "off")  # only partial changes


def test_scan_reading_reaches_the_finding_text():
    d = data(detection={"settings": {}, "hunts": {}, **_scan()})
    from score import v_anomaly
    f = v_anomaly({**d, "_status": OK})
    assert f and "scanned 30 of 100" in f["evidence"] and "cluster" not in f["evidence"].lower().split("scanned")[1]
