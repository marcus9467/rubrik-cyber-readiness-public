import copy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from score import score  # noqa: E402
from test_score import hardened  # noqa: E402


def offsite_bundle(relic, archived):
    b = copy.deepcopy(hardened())
    b["data"]["offsite"].update({"objects": 100, "objectsReplicationKnown": 100, "noReplication": 90})
    b["data"]["inventory"]["reconciliation"] = {"snappables": {"activeProtected": 40, "relic": relic,
                                                               "archived": archived}}
    return b


def test_offsite_finding_says_relics_are_counted_when_there_are_any():
    f = next(x for x in score(offsite_bundle(50, 10))["findings"] if x["id"] == "RP-1")
    assert "relic and archived" in f["evidence"] and "40 active protected" in f["evidence"]
    assert "60 relic or archived" in f["evidence"]


def test_offsite_finding_has_no_relic_note_without_relics_or_inventory():
    f = next(x for x in score(offsite_bundle(0, 0))["findings"] if x["id"] == "RP-1")
    assert "relic" not in f["evidence"]
    b = offsite_bundle(50, 10)
    del b["data"]["inventory"]["reconciliation"]
    f = next(x for x in score(b)["findings"] if x["id"] == "RP-1")
    assert "relic" not in f["evidence"]
