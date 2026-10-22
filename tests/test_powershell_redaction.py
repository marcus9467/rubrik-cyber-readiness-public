"""The customer runs the PowerShell redactor, not redact.py, and nothing else in the suite exercised it.

A cluster name left in the redacted file is a leak in the one file the customer sends. That shipped once, so this
runs the real script end to end against the mock RSC and checks the redacted file it writes. Skipped when pwsh is
not installed.
"""
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Real names the mock serves. None may appear in a redacted bundle.
NAMES = ("nyc-01", "philly-01", "rcv-az", "acme-philly", "acme-epic-db01", "jane.doe", "Acme-Offsite-Gold")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_mock_and_collect(tmp):
    port = _free_port()
    mock = subprocess.Popen([sys.executable, str(ROOT / "tests" / "mock_rsc.py"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    try:
        sa = ROOT / "tests" / ".mock-sa.json"
        for _ in range(50):
            if sa.exists():
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    pass
            time.sleep(0.1)
        py = subprocess.run([sys.executable, str(ROOT / "collect.py"), "--sa", str(sa), "--customer", "PY",
                             "--redact", "--out", str(tmp)], capture_output=True, text=True, timeout=120)
        ps = subprocess.run(["pwsh", "-NoProfile", "-File", str(ROOT / "Invoke-CyberReadiness.ps1"),
                             "-ServiceAccount", str(sa), "-Customer", "PS", "-Redact", "-Out", str(tmp)],
                            capture_output=True, text=True, timeout=180)
        return py, ps
    finally:
        mock.terminate()


def test_powershell_redacted_bundle_has_no_real_names_and_matches_python():
    if not shutil.which("pwsh"):
        print("skipped: pwsh not installed")
        return
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        py, ps = _run_mock_and_collect(d)
        assert py.returncode == 0, py.stderr[-400:]
        assert ps.returncode == 0, (ps.stdout + ps.stderr)[-400:]
        py_red = json.loads((d / "PY" / "bundle.redacted.json").read_text())
        ps_red = json.loads((d / "PS" / "bundle.redacted.json").read_text())
        for label, red in (("python", py_red), ("powershell", ps_red)):
            text = json.dumps(red)
            for n in NAMES:
                assert n not in text, f"{label} redacted bundle leaks {n}"
        # The cluster to archive join must survive redaction in the customer-side collector too.
        ids = {c["id"] for c in ps_red["data"]["clusters"]["clusters"]}
        targets = [t for s in ps_red["data"]["offsite"]["slas"] for t in s["archiveTargets"]]
        assert targets and all(t["clusterId"] in ids for t in targets), "archive clusterId no longer joins"
        cdm = ps_red["data"]["threat"]["roots"]["CDM_CLUSTER"]
        assert {i["id"] for i in cdm["items"] + cdm["notAssessed"]} <= ids, "CDM threat clusters not pseudonymized"
