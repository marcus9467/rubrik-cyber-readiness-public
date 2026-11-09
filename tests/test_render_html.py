"""HTML brief: content and escaping. Builds the HTML only, so no Chrome is needed."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from render_html import build_html  # noqa: E402
from score import score  # noqa: E402
from test_score import hardened  # noqa: E402
from test_delta import ALL_OK  # noqa: E402


def bundle(**clusters):
    b = hardened()
    b["status"] = dict(ALL_OK)
    b["data"]["clusters"].update(clusters)
    return b


def test_every_finding_id_appears_in_the_html():
    b = bundle(encryptionOff=1, supportTunnelOpen=1)
    html, result = build_html(b)
    assert result["findings"], "fixture should produce findings"
    for f in result["findings"]:
        assert f["id"] in html, f["id"]


def test_capability_tile_names_what_is_missing_and_separates_off_from_blind():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")          # blind: RSC does not report it
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0].update(value=0)  # off: reported, nothing enabled
    html, _ = build_html(b)
    assert "1 of 3" in html
    assert "No data: Sensitive Data Discovery" in html
    assert "Off: Anomaly Detection" in html
    assert "detection capabilities returned no data" not in html  # the old tile counted off as no data


def test_headline_separates_off_from_blind():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")          # blind
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0].update(value=0)  # off
    html, _ = build_html(b)
    assert "2 of 3 detection capabilities are not working: 1 returned no data and 1 is switched off." in html
    assert "There is no data in RSC for Sensitive Data Discovery. Anomaly Detection is switched off." in html


def test_headline_for_off_only_does_not_say_returned_nothing():
    b = bundle()
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0].update(value=0)
    html, _ = build_html(b)
    assert "1 of 3 detection capabilities is switched off." in html
    assert "returned nothing" not in html
    assert "no data in RSC" not in html


def test_headline_for_blind_only_keeps_returned_nothing():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")
    html, _ = build_html(b)
    assert "1 of 3 detection capabilities returned nothing." in html


def test_hunt_note_is_shown_unscored_and_never_as_a_card_or_alarm():
    b = bundle()
    b["data"]["detection"]["hunts"] = {"total": 0, "last90": 0, "latest": None}
    html, result = build_html(b)
    assert "Threat hunting (not scored)." in html and "No threat hunt has been run on this tenant." in html
    assert 'class="alarm"' not in html and "Threat Hunting" not in html
    assert all(c["state"] == "active" for c in result["capabilities"].values())


def test_hunt_note_is_absent_when_hunt_history_is_unknown():
    b = bundle()
    b["data"]["detection"]["hunts"] = {"error": "denied"}
    html, _ = build_html(b)
    assert "Threat hunting (not scored)" not in html


def test_card_score_matches_the_area_table_and_explains_a_lower_area_score():
    b = bundle()
    for m in b["data"]["dhrc"]["scores"]["SENSITIVE_DATA"]["metrics"]:
        if m["metric"] == "OPEN_ACCESS_SENSITIVE_FILES":
            m.update(value=4, maxValue=10)
    html, result = build_html(b)
    area = result["domain_scores"]["Sensitive Data Discovery"]
    assert result["capabilities"]["Sensitive Data Discovery"]["score"] == 100 and area < 100
    assert f'<div class="sc">{area}<small> / 100</small>' in html
    assert f"Coverage is 100 of 100. The area score is lower because of open findings in this area: T-2." in html


def test_card_has_no_explanation_when_the_area_score_equals_coverage():
    html, _ = build_html(bundle())
    assert "The area score is lower" not in html


def test_blind_card_shows_its_reason_and_active_cards_do_not():
    b = bundle()
    b["data"]["dhrc"]["scores"].pop("SENSITIVE_DATA")
    html, _ = build_html(b)
    assert html.count("Why no data:") == 1
    assert "RSC does not report this capability for the tenant." in html
    assert "hidden from the account" not in html


def live_tenant_bundle():
    """Shape seen on a live tenant: score buckets returned with no per-cluster metrics, nothing on threat."""
    b = bundle()
    for k in ("ANOMALIES_DETECTED", "SENSITIVE_DATA"):
        b["data"]["dhrc"]["scores"][k] = {"value": 100, "metrics": []}
    b["data"]["threat"]["roots"] = {"CDM_CLUSTER": {"total": 10, "threatMonitoringEnabled": 0, "items": [],
                                                         "notAssessed": []}}
    return b


def test_unlicensed_and_confirmed_report_reads_one_of_three():
    html, result = build_html(live_tenant_bundle(), not_licensed=("Threat Monitoring", "Sensitive Data Discovery"),
                              confirmed_active=("Anomaly Detection",))
    caps = result["capabilities"]
    assert [caps[d]["score"] for d in caps] == [100, 0, 0]
    assert "1 of 3" in html
    assert html.count("Requires Enterprise Edition.") == 2
    assert "Not licensed" in html and "confirmed on by your Rubrik team" in html
    assert not [f for f in result["findings"] if f["domain"] in ("Threat Monitoring", "Sensitive Data Discovery")]


def test_unverified_card_is_not_scored_and_not_counted():
    b = bundle()
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"] = {"value": 100, "metrics": []}
    html, result = build_html(b)
    assert result["capabilities"]["Anomaly Detection"]["state"] == "unverified"
    assert "Not verified" in html and "Not scored:" in html
    assert "Data collection failed" not in html


def test_tile_for_a_fully_active_tenant():
    html, result = build_html(bundle())
    assert all(c["state"] == "active" for c in result["capabilities"].values())
    assert "3 of 3" in html and "all fully covered" in html


def test_untrusted_text_is_escaped():
    b = bundle()
    b["data"]["inventory"]["unprotected"]["rows"] = [
        {"objectType": "ACTIVE_DIRECTORY_DOMAIN_CONTROLLER", "name": "<script>alert(1)</script>",
         "protectionStatus": "NoSla", "clusterName": "c"}]
    html, _ = build_html(b)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_no_literal_entities_or_unrendered_placeholders():
    html, _ = build_html(bundle(encryptionOff=1))
    body = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
    assert "__" not in body
    assert "&amp;nbsp;" not in body and "&amp;lt;" not in body


def test_nothing_is_called_enterprise_edition_without_a_confirmed_entitlement():
    b = bundle()
    b["data"]["threat"] = {"roots": {"AWS_NATIVE_ACCOUNT": {"total": 2, "threatMonitoringEnabled": 1}}}
    html, result = build_html(b)
    t1 = next(f for f in result["findings"] if f["id"] == "T-1")
    assert t1["bucket"] == "visibility"
    # The report scopes to what the tenant can see. It must never claim an edition entitlement it has not confirmed.
    assert "Capability requires Enterprise Edition" not in html
    assert "Enterprise Edition benefit" not in html


def test_not_assessed_area_is_called_out_and_not_scored_clean():
    b = bundle()
    b["status"]["recovery"] = "error: denied"
    html, _ = build_html(b)
    assert "Not assessed:" in html and "Recovery" in html


def test_progress_section_only_with_a_previous_bundle():
    html, _ = build_html(bundle())
    assert "Progress since last run" not in html
    html, _ = build_html(bundle(encryptionOff=1), previous=bundle())
    assert "Progress since last run" in html


def test_posture_score_matches_the_scorer():
    b = bundle(encryptionOff=1)
    html, result = build_html(b)
    assert f"{len(result['findings'])}</div>" in html
    assert score(b)["counts"] == result["counts"]


def _appendix(html):
    return html.split("Appendix. Technical findings")[1].split("Method and limits")[0]


def test_every_finding_has_an_appendix_entry_including_the_capability_areas():
    # The roadmap lists every id, so an id appearing anywhere in the html proves nothing. Check the appendix itself.
    b = bundle(encryptionOff=1, supportTunnelOpen=1)
    b["data"]["dhrc"]["scores"]["ANOMALIES_DETECTED"]["metrics"][0]["value"] = 0  # off, so V-1 fires
    html, result = build_html(b)
    cap = {"Anomaly Detection", "Threat Monitoring", "Sensitive Data Discovery"}
    ids = [f["id"] for f in result["findings"]]
    assert any(f["domain"] in cap for f in result["findings"]), "fixture should produce a capability finding"
    appendix = _appendix(html)
    missing = [i for i in ids if f">{i}<" not in appendix and f"{i} " not in appendix]
    assert not missing, missing


def test_appendix_domains_orders_known_areas_and_keeps_unknown_ones():
    from posture import DOMAIN_ORDER, appendix_domains
    out = appendix_domains([{"domain": "Recovery"}, {"domain": "Zebra"}, {"domain": "Identity"},
                            {"domain": "Anomaly Detection"}])
    assert out == [d for d in DOMAIN_ORDER if d in ("Identity", "Anomaly Detection", "Recovery")] + ["Zebra"]
    assert appendix_domains([]) == []
