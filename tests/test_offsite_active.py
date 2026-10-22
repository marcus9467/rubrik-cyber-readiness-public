import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collectors import offsite  # noqa: E402
from score import score  # noqa: E402
from test_score import hardened  # noqa: E402


class FakeClient:
    """Two SLAs: a-1 has 100 records but 40 active, a-2 only relic records (0 active), a-3's count fails."""
    def __init__(self, counts, fail=()):
        self.counts, self.fail = counts, set(fail)

    def paginate(self, q, path):
        mk = lambda i, n, repl: {"id": i, "name": i, "protectedObjectCount": n, "isArchived": False,
                                 "replicationSpecsV2": [{"cluster": {"name": "c"}, "targetMapping": {}}] if repl else [],
                                 "archivalSpecs": []}
        return [mk("a-1", 100, False), mk("a-2", 30, False), mk("a-3", 20, True)]

    def query(self, q, v):
        sid = v["f"]["slaDomain"]["id"][0]
        assert v["f"]["objectState"] == ["ACTIVE"] and v["f"]["protectionStatus"] == ["Protected"]
        if sid in self.fail:
            raise RuntimeError("denied")
        return {"snappableConnection": {"count": self.counts[sid]}}


def test_active_count_replaces_record_count_and_relic_only_slas_drop_out():
    o = offsite.collect(FakeClient({"a-1": 40, "a-2": 0, "a-3": 10}))
    assert o["basis"] == "active-protected" and o["fallbackSlas"] == 0
    assert o["objects"] == 50 and o["recordCount"] == 120  # a-2 dropped, a-1 and a-3 kept
    assert [s["name"] for s in o["slas"]] == ["a-1", "a-3"]
    assert o["noReplication"] == 40 and o["withReplication"] == 10


def test_failed_count_falls_back_to_record_count_and_is_flagged_not_hidden():
    o = offsite.collect(FakeClient({"a-1": 40, "a-2": 0, "a-3": 10}, fail=["a-1"]))
    assert o["fallbackSlas"] == 1
    assert next(s for s in o["slas"] if s["name"] == "a-1")["objects"] == 100  # record count, unknown is not zero


def bundle(**off):
    b = copy.deepcopy(hardened())
    b["data"]["offsite"].update({"objects": 100, "objectsReplicationKnown": 100, "noReplication": 90, **off})
    return b


def rp1(b):
    return next(f for f in score(b)["findings"] if f["id"] == "RP-1")["evidence"]


def test_finding_says_active_protected_objects_when_the_basis_is_active():
    e = rp1(bundle(basis="active-protected", fallbackSlas=0))
    assert "90 of 100 active protected objects" in e and "relic" not in e


def test_finding_flags_fallback_slas():
    e = rp1(bundle(basis="active-protected", fallbackSlas=2))
    assert "object records" in e and "For 2 SLAs the active count could not be read" in e


def test_old_bundle_without_basis_keeps_the_relic_caveat():
    b = bundle()
    b["data"]["inventory"]["reconciliation"] = {"snappables": {"activeProtected": 40, "relic": 50, "archived": 10}}
    e = rp1(b)
    assert "relic and archived" in e and "40 active protected" in e
