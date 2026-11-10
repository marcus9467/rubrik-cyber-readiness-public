"""Archive storage: RCV against the customer's own cloud, and the RCV entitlement."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from collectors import archive  # noqa: E402
from redact import redact_bundle  # noqa: E402
from test_score import hardened  # noqa: E402

TB = 1e12
NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


def tgt(ttype, tb, status="READ_WRITE", name="loc"):
    return {"id": name, "name": name, "type": ttype, "bytes": int(tb * TB), "status": status,
            "readOnly": status == "READ_ONLY"}





def test_collector_records_each_query_separately_and_flags_read_only():
    class C:
        def paginate(self, gql, path, variables=None):
            return [{"id": "1", "name": "n", "targetType": "AWS", "consumedBytes": 5, "status": "READ_ONLY"}]

        def query(self, gql, variables=None):
            raise RuntimeError("denied")
    out = archive.collect(C())
    assert out["targets"][0]["readOnly"] is True and out["targets"][0]["bytes"] == 5
    assert "error" in out["entitlements"]
