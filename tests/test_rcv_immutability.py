"""RCV immutability: blob, container, none, and not reported. RSC reports it only for RCV on Azure."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_report as inv  # noqa: E402
from render_html import build_html  # noqa: E402
from score import score  # noqa: E402
from test_delta import ALL_OK  # noqa: E402
from test_score import hardened  # noqa: E402

TB = 1e12
NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


def rcv(blob, days, ttype="RCS_AZURE", name="r"):
    t = {"id": name, "name": name, "type": ttype, "bytes": int(TB), "status": "READ_WRITE", "readOnly": False}
    if blob is not None:
        t.update(tier="BACKUP", blobImmutable=blob, lockDays=days)
    return t


def bundle(*targets):
    b = hardened()
    b["status"] = dict(ALL_OK)
    b["data"]["archive"] = {"targets": list(targets), "entitlements": []}
    return b


def s3(b):
    return next((f for f in score(b)["findings"] if f["id"] == "S-3"), None)


def test_each_state_follows_rsc_fields():
    assert inv.rcv_immutability(rcv(True, 0)) == "blob"
    assert inv.rcv_immutability(rcv(True, 150)) == "blob"          # blob wins over a lock period
    assert inv.rcv_immutability(rcv(False, 100)) == "container"
    assert inv.rcv_immutability(rcv(False, 0)) == "none"
    assert inv.rcv_immutability(rcv(False, None)) == "none"


def test_aws_and_gcp_rcv_and_old_bundles_are_not_reported_never_none():
    assert inv.rcv_immutability(rcv(None, None, "RCV_AWS")) == "not_reported"
    assert inv.rcv_immutability(rcv(None, None, "RCV_GCP")) == "not_reported"
    assert inv.rcv_immutability(rcv(None, None, "RCS_AZURE")) == "not_reported"   # bundle without the fields
    assert inv.rcv_immutability({"type": "AWS", "blobImmutable": False, "lockDays": 0}) == "not_reported"


def test_roll_up_counts_only_rcv_targets():
    d = {"archive": {"targets": [rcv(True, 0, name="a"), rcv(False, 100, name="b"), rcv(False, 0, name="c"),
                                 rcv(None, None, "RCV_AWS", name="d"),
                                 {"id": "e", "name": "e", "type": "AWS", "bytes": 5, "status": "READ_WRITE",
                                  "readOnly": False}], "entitlements": []}}
    t = inv.archive_storage(d, NOW)["targets"]
    assert t["rcvImmutability"] == {"blob": 1, "container": 1, "none": 1, "not_reported": 1}


def test_s3_fires_only_for_locations_rsc_reports_as_not_immutable():
    f = s3(bundle(rcv(True, 0, name="a"), rcv(False, 0, name="b"), rcv(False, 0, name="c")))
    assert f and f["severity"] == "high" and f["bucket"] == "fix_now" and f["domain"] == "Immutability"
    assert "2 of 3 Rubrik Cloud Vault locations have no immutability" in f["evidence"]
    assert f["steps"] and f["docs"]


def test_s3_does_not_fire_for_blob_container_or_unreported_locations():
    assert s3(bundle(rcv(True, 0), rcv(False, 100), rcv(None, None, "RCV_AWS"), rcv(None, None, "RCV_GCP"))) is None
    assert s3(bundle()) is None


def test_s3_names_container_level_locations_without_counting_them_as_gaps():
    f = s3(bundle(rcv(False, 0, name="a"), rcv(False, 100, name="b")))
    assert "1 of 2" in f["evidence"] and "A further 1 use container-level immutability" in f["evidence"]


def test_s3_is_absent_for_a_bundle_without_the_archive_section():
    b = hardened()
    b["status"] = dict(ALL_OK)
    assert s3(b) is None


def test_s3_has_a_framework_tag_and_costs_a_scored_area_like_any_other_high_finding():
    b = bundle(rcv(False, 0))
    f = s3(b)
    assert f["framework"] and f["framework"]["csf"]
    assert "Immutability" not in score(bundle(rcv(True, 0)))["domain_scores"]    # no findings: posture defaults it to 100
    assert score(b)["domain_scores"]["Immutability"] == 85                        # 100 less 15 for one high finding


def test_report_shows_the_immutability_line_and_appendix_column():
    html, _ = build_html(bundle(rcv(True, 0, name="a"), rcv(False, 100, name="b"), rcv(False, 0, name="c"),
                                rcv(None, None, "RCV_AWS", name="d")))
    assert ("RCV immutability.</b> 1 with blob-level immutability; 1 with container-level immutability "
            "(deprecated); 1 with no immutability; 1 where RSC does not report immutability.") in html
    for label in ("Blob-level", "Container-level (deprecated)", "None", "Not reported by RSC"):
        assert f"<td>{label}</td>" in html
    assert "<th>Immutability</th>" in html


def test_the_callout_names_immutability_and_no_longer_ties_deletion_to_retention_lock_or_quorum():
    html, _ = build_html(bundle(rcv(True, 0)))
    callout = html.split("Why RCV matters.")[1].split("</div>")[0]
    assert "immutability stops snapshots being altered or deleted" in callout
    assert "retention lock" not in callout and "quorum" not in callout
