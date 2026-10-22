"""Tier-0 detection: structural types, name matching, and the false positives it must avoid."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tier0 import classify, find  # noqa: E402
from test_score import hardened, ids  # noqa: E402


def vm(name, t="VmwareVirtualMachine", status="NoSla", cluster="c1"):
    return {"objectType": t, "name": name, "protectionStatus": status, "clusterName": cluster}


def test_structural_type_is_high_confidence():
    assert classify(vm("anything", "ACTIVE_DIRECTORY_DOMAIN_CONTROLLER")) == ("Active Directory domain controller", "structural")


def test_name_matches():
    for n in ("DC01", "prod-dc-2", "rp-nbspo-adds01", "ad-m-child-01", "TNT51-VCENTER", "corp-pki01", "dns02"):
        assert classify(vm(n)) is not None, n


def test_false_positives_are_not_matched():
    for n in ("adobe-01", "dcim01", "ad-hoc-01", "paddock01", "address-svc"):
        assert classify(vm(n)) is None, n


def test_test_and_restore_copies_are_not_tier0():
    assert classify(vm("rp-ad-tst-01")) is None
    assert classify(vm("rp-ad-restore01")) is None
    assert classify(vm("dc01-test")) is None


def test_only_vm_like_types_are_name_matched():
    assert classify(vm("dc01", "AzureNativeManagedDisk")) is None
    assert classify(vm("vcsa-volumes", "PURE_STORAGE_PROTECTION_GROUP")) is None


def test_find_dedupes_rows_seen_from_several_clusters():
    out = find([vm("dc01", cluster="a"), vm("dc01", cluster="b", status="DoNotProtect")])
    assert len(out) == 1 and out[0]["clusters"] == ["a", "b"] and out[0]["statuses"] == ["DoNotProtect", "NoSla"]


def test_structural_sorts_first():
    out = find([vm("dc01"), vm("x", "ACTIVE_DIRECTORY_DOMAIN_CONTROLLER")])
    assert out[0]["confidence"] == "structural"


def _with_rows(rows):
    b = hardened()
    b["data"]["inventory"]["unprotected"]["rows"] = rows
    return b


def test_c4_severity_follows_confidence():
    from score import score
    f = next(f for f in score(_with_rows([vm("dc01")]))["findings"] if f["id"] == "C-4")
    assert f["severity"] == "high"
    rows = [vm("x", "ACTIVE_DIRECTORY_DOMAIN_CONTROLLER")]
    f = next(f for f in score(_with_rows(rows))["findings"] if f["id"] == "C-4")
    assert f["severity"] == "critical"


def test_c4_silent_without_rows_or_candidates():
    assert "C-4" not in ids(hardened())
    assert "C-4" not in ids(_with_rows([vm("webapp01")]))
