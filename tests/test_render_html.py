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
