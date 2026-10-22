import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collectors import inventory  # noqa: E402
from test_score import hardened, score  # noqa: E402


class FakeClient:
    def __init__(self, rows):
        self.rows = rows

    def paginate(self, gql, path, variables=None):
        return [dict(r) for r in self.rows]


def row(i, name="x", cluster="c1", otype="Mssql", status="NoSla"):
    return {"id": i, "name": name, "objectType": otype, "location": "loc", "protectionStatus": status,
            "complianceStatus": "EMPTY", "logicalBytes": 10, "cluster": {"id": cluster, "name": cluster}}


def test_dedupe_by_id_collapses_same_object_seen_from_two_clusters():
    rows = [row("a", cluster="c1"), row("a", cluster="c2"), row("b")]
    out = inventory._dedupe_by_id(rows)
    assert [r["id"] for r in out] == ["a", "b"]


def test_dedupe_does_not_merge_same_name_different_id():
    # Azure DevOps shape: same repo name in ten projects, ten distinct ids, one cluster and location.
    rows = [row(f"id{i}", name="repo-001", otype="AZURE_DEVOPS_REPOSITORY") for i in range(10)]
    assert len(inventory._dedupe_by_id(rows)) == 10


def test_totp_finding_cites_cockpit_when_present():
    b = hardened()
    b["data"]["identity"]["users"] = [
        {"domain": "LOCAL", "isAccountOwner": False, "lastLogin": None,
         "totpStatus": {"isSupported": True, "isEnabled": False}}]
    b["data"]["dhrc"] = {"scores": {"SECURITY_CONFIG": {"value": 85.2, "metrics": [
        {"metric": "USERS_USING_TOTP", "value": 52, "maxValue": 61}]}}}
    f = next(f for f in score(b)["findings"] if f["id"] == "ID-1")
    assert "1 of 1 local" in f["evidence"] and "52 of 61" in f["evidence"]


def test_totp_finding_still_fires_when_cockpit_value_is_null():
    b = hardened()
    b["data"]["identity"]["users"] = [
        {"domain": "LOCAL", "isAccountOwner": False, "lastLogin": None,
         "totpStatus": {"isSupported": True, "isEnabled": False}}]
    b["data"]["dhrc"] = {"scores": {"SECURITY_CONFIG": {"value": 85.2, "metrics": [
        {"metric": "USERS_USING_TOTP", "value": None, "maxValue": 61}]}}}
    r = score(b)
    assert r["skipped_rules"] == []
    f = next(f for f in r["findings"] if f["id"] == "ID-1")
    assert "cockpit" not in f["evidence"]
