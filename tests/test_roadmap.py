"""Roadmap phases, projections and the framework mapping."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from frameworks import CSF_NAMES, MAP, framework_of  # noqa: E402
from roadmap import phase_of, plan, projected_overall, projections  # noqa: E402

SCORE_SRC = (Path(__file__).resolve().parent.parent / "score.py").read_text()


def f(fid, domain, sev, bucket):
    return {"id": fid, "domain": domain, "severity": sev, "bucket": bucket}


def test_phase_rules():
    assert phase_of(f("a", "X", "high", "fix_now")) == 30
    assert phase_of(f("a", "X", "medium", "fix_now")) == 60
    assert phase_of(f("a", "X", "high", "process")) == 60
    assert phase_of(f("a", "X", "low", "process")) == 90
    assert phase_of(f("a", "X", "high", "enterprise")) == "decide"
    assert phase_of(f("a", "X", "high", "unconfirmed")) == "decide"
    assert phase_of(f("a", "X", "info", "fix_now")) is None


def test_plan_skips_info_and_groups():
    p = plan([f("a", "X", "info", "process"), f("b", "X", "high", "fix_now")])
    assert [x["id"] for x in p[30]] == ["b"] and not p[60] and not p[90] and not p["decide"]


def test_projection_is_cumulative_and_ignores_edition_gated_findings():
    fs = [f("a", "X", "high", "fix_now"), f("b", "X", "medium", "fix_now"),
          f("c", "Y", "high", "enterprise")]
    rows = dict(projections(fs, ["X", "Y"]))
    assert rows["Today"] == round((100 - 22 + 100 - 15) / 2)
    assert rows["After 30 days"] == round((100 - 7 + 100 - 15) / 2)
    assert rows["After 90 days"] == round((100 + 100 - 15) / 2)  # Y never assumed fixed


def test_projection_with_no_assessed_domains_is_none():
    assert projected_overall([], []) is None


def test_every_rule_id_has_a_framework_mapping():
    ids = set(re.findall(r'_f\("([A-Z]+-[0-9]+)"', SCORE_SRC))
    assert ids, "no rule ids found"
    assert ids <= set(MAP), sorted(ids - set(MAP))


def test_framework_codes_are_valid_and_unmapped_is_empty():
    assert all(csf in CSF_NAMES for csf, _ in MAP.values())
    assert framework_of("NOPE-9") == {"csf": None, "hipaa": []}
