import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import inventory_report as inv  # noqa: E402
from collectors import offsite  # noqa: E402
from redact import redact_bundle  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_score import hardened  # noqa: E402


def cluster(cid, name, version="9.6.1-p1-33607", status="Connected", eos="EOS_STATUS_UNKNOWN", date="unknown"):
    return {"id": cid, "name": name, "type": "OnPrem", "productType": "CDM", "version": version,
            "status": status, "isHealthy": True, "eosStatus": eos, "eosDate": date, "estimatedRunway": 900}


def target(cid, ttype, name="loc"):
    return {"name": name, "type": ttype, "clusterId": cid, "immutable": False}


def data(clusters, slas):
    return {"clusters": {"total": len(clusters), "clusters": clusters}, "offsite": {"slas": slas}}


def sla(name, objects, *targets):
    return {"name": name, "objects": objects, "archiveTargets": list(targets)}


def test_rcv_is_recognised_by_target_type_for_all_three_rcv_types():
    d = data([cluster("a", "a"), cluster("b", "b"), cluster("c", "c"), cluster("d", "d")],
             [sla("s1", 10, target("a", "RCS_AZURE")), sla("s2", 5, target("b", "RCV_AWS")),
              sla("s3", 3, target("c", "RCV_GCP")), sla("s4", 8, target("d", "AWS"))])
    rows = {r["id"]: r for r in inv.cluster_rows(d)}
    assert [rows[k]["toRcv"] for k in "abcd"] == [True, True, True, False]
    assert rows["a"]["objectsUnderRcvSlas"] == 10 and rows["d"]["objectsUnderRcvSlas"] == 0


def test_a_location_named_rcv_that_is_plain_aws_is_not_rcv():
    d = data([cluster("a", "a")], [sla("s", 4, target("a", "AWS", name="RCV-Immutable-Archive"))])
    assert inv.cluster_rows(d)[0]["toRcv"] is False


def test_sla_counted_once_per_cluster_and_objects_summed_across_slas():
    d = data([cluster("a", "a")],
             [sla("s1", 10, target("a", "RCS_AZURE"), target("a", "RCV_AWS")), sla("s2", 5, target("a", "RCS_AZURE"))])
    r = inv.cluster_rows(d)[0]
    assert (r["rcvSlas"], r["objectsUnderRcvSlas"]) == (2, 15)


def test_unknown_end_of_support_is_never_shown_as_supported_or_as_a_date():
    r = inv.cluster_rows(data([cluster("a", "a")], []))[0]
    assert r["eos"] == {"label": "Not reported", "date": None, "known": False}
    soon = inv.cluster_rows(data([cluster("b", "b", eos="EOS_STATUS_PLAN_UPGRADE", date="2027-01-14")], []))[0]
    assert soon["eos"] == {"label": "Plan upgrade", "date": "2027-01-14", "known": True}


def test_version_is_kept_whole_and_grouped_by_base():
    rows = inv.cluster_rows(data([cluster("a", "a", "9.6.1-p1-33607"), cluster("b", "b", "9.6.1-p2-1"),
                                  cluster("c", "c", "9.4.2-p3-31101_HP57dd9cf")], []))
    assert [r["version"] for r in rows][0] == "9.6.1-p1-33607"
    assert [r["baseVersion"] for r in rows] == ["9.6.1", "9.6.1", "9.4.2"]
    assert inv.summary(data([cluster("a", "a"), cluster("b", "b", "9.4.2-p3-1")], []))["versions"] == {"9.6.1": 1, "9.4.2": 1}


def test_old_bundle_without_cluster_ids_says_unknown_instead_of_not_going_to_rcv():
    old = [{"name": "x", "type": "RCS_AZURE", "immutable": False}]  # no clusterId, as collected before this change
    d = data([cluster("a", "a")], [sla("s", 4, *old)])
    assert inv.rcv_known(d) is False
    s = inv.summary(d)
    assert s["rcvKnown"] is False and s["toRcv"] is None and s["notToRcv"] is None


def test_no_archive_targets_at_all_is_a_known_zero():
    s = inv.summary(data([cluster("a", "a"), cluster("b", "b")], [sla("s", 4)]))
    assert (s["rcvKnown"], s["toRcv"], s["notToRcv"]) == (True, 0, 2)


def test_missing_or_errored_sections_give_no_rows_and_no_summary():
    assert inv.cluster_rows({}) == [] and inv.summary({}) is None
    assert inv.cluster_rows({"clusters": {"error": "denied"}}) == []
    d = {"clusters": {"clusters": [cluster("a", "a")]}, "offsite": {"error": "denied"}}
    assert inv.rcv_known(d) is False and inv.summary(d)["toRcv"] is None


def test_collector_stores_the_cluster_id_on_each_archive_target():
    specs = [{"isComplianceImmutabilityEnabled": True, "archivalLocationToClusterMapping": [
        {"cluster": {"id": "c-1"}, "location": {"name": "L", "targetType": "RCS_AZURE"}},
        {"location": {"name": "M", "targetType": "AWS"}}]}]
    out = offsite._archive_targets(specs)
    assert out[0] == {"name": "L", "type": "RCS_AZURE", "clusterId": "c-1", "immutable": True}
    assert out[1]["clusterId"] is None, "a mapping with no cluster is unknown, so it cannot join to a cluster"


def test_redaction_keeps_the_cluster_to_rcv_join_and_hides_names():
    b = hardened()
    b["data"]["clusters"] = {"total": 2, "clusters": [cluster("real-id-a", "acme-philly-01"),
                                                      cluster("real-id-b", "acme-nyc-01")]}
    b["data"]["offsite"] = {"slas": [sla("Acme-Gold", 10, target("real-id-a", "RCS_AZURE", "acme-rcv-vault"))]}
    before = {r["name"]: r["toRcv"] for r in inv.cluster_rows(b["data"])}
    red, _ = redact_bundle(b)
    text = json.dumps(red)
    for leaked in ("real-id-a", "real-id-b", "acme-philly", "acme-nyc", "acme-rcv-vault", "Acme-Gold"):
        assert leaked not in text, leaked
    rows = inv.cluster_rows(red["data"])
    assert sorted(r["toRcv"] for r in rows) == [False, True], "the join must survive redaction"
    assert sum(before.values()) == sum(r["toRcv"] for r in rows)
    assert rows[0]["version"] == "9.6.1-p1-33607", "versions are not identifying and must survive"


def test_every_value_of_rscs_eos_enum_gets_a_specific_label():
    # The four values of ClusterEosStatus. Out of support must never fall through to a vague generic label.
    want = {"EOS_STATUS_SUPPORTED": "Supported", "EOS_STATUS_PLAN_UPGRADE": "Plan upgrade",
            "EOS_STATUS_UNSUPPORTED": "Out of support", "EOS_STATUS_UNKNOWN": "Not reported"}
    for status, label in want.items():
        r = inv.cluster_rows(data([cluster("a", "a", eos=status, date="2027-01-14")], []))[0]
        assert r["eos"]["label"] == label, status
    assert inv.cluster_rows(data([cluster("a", "a", eos="EOS_STATUS_UNKNOWN")], []))[0]["eos"]["known"] is False
