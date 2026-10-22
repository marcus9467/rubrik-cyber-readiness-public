"""Archive storage: RCV against the customer's own cloud, and the RCV entitlement."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_report as inv  # noqa: E402
from collectors import archive  # noqa: E402
from redact import redact_bundle  # noqa: E402
from render_html import archive_summary, build_html  # noqa: E402
from test_delta import ALL_OK  # noqa: E402
from test_score import hardened  # noqa: E402

TB = 1e12
NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


def tgt(ttype, tb, status="READ_WRITE", name="loc"):
    return {"id": name, "name": name, "type": ttype, "bytes": int(tb * TB), "status": status,
            "readOnly": status == "READ_ONLY"}


def ent(tier, cap, used, replaced=False, expires="2030-01-01T00:00:00.000Z"):
    return {"tier": tier, "capacityTb": cap, "usedTb": used, "replaced": replaced, "expires": expires}


def bundle_with(archive_section):
    b = hardened()
    b["status"] = dict(ALL_OK)
    b["data"]["archive"] = archive_section
    return b


def test_rcv_and_own_cloud_are_split_by_type_and_read_only_is_left_out():
    d = {"archive": {"targets": [tgt("RCS_AZURE", 2), tgt("RCV_AWS", 1), tgt("RCV_GCP", 1), tgt("AWS", 6),
                                 tgt("AZURE", 2), tgt("GOOGLE", 0), tgt("AWS", 9, status="READ_ONLY")],
                     "entitlements": []}}
    t = inv.archive_storage(d, NOW)["targets"]
    assert t["rcv"] == {"count": 3, "inUse": 3, "tb": 4.0} and t["other"]["count"] == 0
    assert t["own"] == {"count": 3, "inUse": 2, "tb": 8.0}
    assert t["rcvShare"] == 4 / 12 and t["readOnly"] == 1


def test_nfs_tape_and_s3_compatible_are_other_storage_not_cloud_account():
    d = {"archive": {"targets": [tgt("RCS_AZURE", 1), tgt("AWS", 2), tgt("NFS", 3), tgt("TAPE", 1),
                                 tgt("S3_COMPATIBLE", 1), tgt("GLACIER", 1), tgt(None, 1)], "entitlements": []}}
    t = inv.archive_storage(d, NOW)["targets"]
    assert t["own"]["tb"] == 3.0 and t["own"]["count"] == 2           # AWS + GLACIER
    assert t["other"] == {"count": 4, "inUse": 4, "tb": 6.0}          # NFS, TAPE, S3_COMPATIBLE, unknown
    assert abs(t["rcvShare"] + t["ownShare"] + t["otherShare"] - 1) < 1e-9


def test_a_target_named_rcv_that_is_plain_aws_is_not_rcv():
    t = inv.archive_storage({"archive": {"targets": [tgt("AWS", 5, name="RCV-vault")], "entitlements": []}}, NOW)["targets"]
    assert t["rcv"]["count"] == 0 and t["own"]["tb"] == 5.0


def test_no_bytes_anywhere_gives_no_share_not_zero_percent():
    t = inv.archive_storage({"archive": {"targets": [tgt("AWS", 0)], "entitlements": []}}, NOW)["targets"]
    assert t["rcvShare"] is None


def test_entitlement_leaves_out_replaced_and_expired_and_sums_by_tier():
    d = {"archive": {"targets": [], "entitlements": [
        ent("BACKUP", 10, 2), ent("BACKUP", 5, 1), ent("ARCHIVE", 5, 0.5),
        ent("BACKUP", 9, 9, replaced=True), ent("ARCHIVE", 4, 4, expires="2025-01-01T00:00:00.000Z")]}}
    e = inv.archive_storage(d, NOW)["entitlement"]
    assert e["tiers"] == {"BACKUP": {"capacityTb": 15.0, "usedTb": 3.0}, "ARCHIVE": {"capacityTb": 5.0, "usedTb": 0.5}}
    assert e["capacityTb"] == 20.0 and e["usedTb"] == 3.5


def test_a_failed_query_is_unknown_not_zero_and_does_not_blank_the_other():
    a = inv.archive_storage({"archive": {"targets": {"error": "denied"}, "entitlements": [ent("BACKUP", 10, 2)]}}, NOW)
    assert a["targets"] is None and a["entitlement"]["capacityTb"] == 10.0
    a = inv.archive_storage({"archive": {"targets": [tgt("AWS", 1)], "entitlements": {"error": "denied"}}}, NOW)
    assert a["entitlement"] is None and a["targets"]["own"]["tb"] == 1.0


def test_an_old_bundle_without_the_section_has_no_archive_block():
    assert inv.archive_storage({}, NOW) is None
    assert archive_summary({}) == ""


def test_summary_states_rcv_is_outside_the_tenancy_and_shows_the_entitlement():
    b = bundle_with({"targets": [tgt("RCS_AZURE", 2.5), tgt("AWS", 7.5)],
                     "entitlements": [ent("BACKUP", 15, 2.5)]})
    html, _ = build_html(b)
    assert "Archive storage" in html and "Outside your cloud tenancy" in html
    assert "2.50 TB" in html and "7.50 TB" in html and "25%" in html and "75%" in html
    assert "2.50 TB used of 15 TB entitled (16.7%)" in html
    assert "credentials for your own cloud accounts do not reach it" in html
    assert "immutability stops snapshots being altered or deleted" in html
    assert "retention lock" not in html.split("Why RCV matters")[1].split("</div>")[0]


def test_summary_says_unknown_when_a_query_failed():
    html, _ = build_html(bundle_with({"targets": {"error": "x"}, "entitlements": {"error": "y"}}))
    assert "Archive consumption is not known" in html and "Not known: the entitlement query returned no data" in html


def test_appendix_marks_read_only_targets_as_not_counted():
    b = bundle_with({"targets": [tgt("AWS", 1, name="a"), tgt("AWS", 2, status="READ_ONLY", name="b")],
                     "entitlements": []})
    html, _ = build_html(b)
    assert "Read-only, not counted" in html and "Read/write" in html and "Read Write" not in html


def test_collector_records_each_query_separately_and_flags_read_only():
    class C:
        def paginate(self, gql, path, variables=None):
            return [{"id": "1", "name": "n", "targetType": "AWS", "consumedBytes": 5, "status": "READ_ONLY"}]

        def query(self, gql, variables=None):
            raise RuntimeError("denied")
    out = archive.collect(C())
    assert out["targets"][0]["readOnly"] is True and out["targets"][0]["bytes"] == 5
    assert "error" in out["entitlements"]


def test_target_names_and_ids_do_not_survive_redaction_but_totals_do():
    b = bundle_with({"targets": [tgt("RCS_AZURE", 2, name="RCV-acme-philly"), tgt("AWS", 3, name="acme-s3")],
                     "entitlements": [ent("BACKUP", 10, 2)]})
    redacted, _ = redact_bundle(b)
    text = str(redacted["data"]["archive"])
    assert "acme" not in text and "RCV-" not in text
    assert inv.archive_storage(redacted["data"], NOW)["targets"]["rcv"]["tb"] == 2.0
