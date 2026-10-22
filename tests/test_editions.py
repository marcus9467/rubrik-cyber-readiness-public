"""Edition entitlement rules: nothing is called Enterprise without a confirmed source."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from editions import EDITIONS, bucket, edition_of  # noqa: E402


def test_unlisted_rule_is_unconfirmed():
    e = edition_of("ID-1")
    assert e["status"] == "unconfirmed" and not e["confirmed"]


def test_unconfirmed_entry_is_not_reported_as_enterprise():
    assert EDITIONS["T-1"]["status"] == "enterprise" and not EDITIONS["T-1"]["confirmed"]
    e = edition_of("T-1")
    assert e["status"] == "unconfirmed"
    assert e["believed"] == "enterprise"


def test_confirmed_entry_without_source_is_not_trusted():
    EDITIONS["X-1"] = {"status": "enterprise", "confirmed": True, "source": "  "}
    try:
        assert edition_of("X-1")["status"] == "unconfirmed"
    finally:
        del EDITIONS["X-1"]


def test_confirmed_entry_with_source_is_enterprise():
    EDITIONS["X-2"] = {"status": "enterprise", "confirmed": True, "source": "price book 2026-10, line 4"}
    try:
        assert edition_of("X-2")["status"] == "enterprise"
        assert bucket("ee_candidate", "X-2") == "enterprise"
        assert bucket("fix_now", "X-2") == "enterprise"
    finally:
        del EDITIONS["X-2"]


def test_buckets_without_entitlement():
    assert bucket("fix_now", "ID-1") == "fix_now"
    assert bucket("process", "CL-3") == "process"
    assert bucket("ee_candidate", "T-2") == "unconfirmed"


def test_every_confirmed_entry_has_a_source():
    for rid, e in EDITIONS.items():
        if e.get("confirmed"):
            assert e.get("source", "").strip(), rid
