import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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


def test_collector_stores_the_cluster_id_on_each_archive_target():
    specs = [{"isComplianceImmutabilityEnabled": True, "archivalLocationToClusterMapping": [
        {"cluster": {"id": "c-1"}, "location": {"name": "L", "targetType": "RCS_AZURE"}},
        {"location": {"name": "M", "targetType": "AWS"}}]}]
    out = offsite._archive_targets(specs)
    assert out[0] == {"name": "L", "type": "RCS_AZURE", "clusterId": "c-1", "immutable": True}
    assert out[1]["clusterId"] is None, "a mapping with no cluster is unknown, so it cannot join to a cluster"


def test_redaction_keeps_the_cluster_to_archive_join_and_hides_names():
    b = hardened()
    b["data"]["clusters"] = {"total": 2, "clusters": [cluster("real-id-a", "acme-philly-01"),
                                                      cluster("real-id-b", "acme-nyc-01")]}
    b["data"]["offsite"] = {"slas": [sla("Acme-Gold", 10, target("real-id-a", "RCS_AZURE", "acme-rcv-vault"))]}
    red, _ = redact_bundle(b)
    text = json.dumps(red)
    for leaked in ("real-id-a", "real-id-b", "acme-philly", "acme-nyc", "acme-rcv-vault", "Acme-Gold"):
        assert leaked not in text, leaked
    ids = {c["id"] for c in red["data"]["clusters"]["clusters"]}
    targets = [t for s in red["data"]["offsite"]["slas"] for t in s["archiveTargets"]]
    assert targets and all(t["clusterId"] in ids for t in targets), "the join must survive redaction"
    assert {c["version"] for c in red["data"]["clusters"]["clusters"]} == {"9.6.1-p1-33607"}, "versions must survive"
