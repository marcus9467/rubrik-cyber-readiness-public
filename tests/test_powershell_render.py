"""The assessor runs Invoke-RenderReport.ps1, and nothing else in the suite exercised it.

It is a thin wrapper over render_pdf.py, so these check what the wrapper itself owns: finding the bundle, passing the
flags through, refusing bad input with a plain message and exit code 1, and delivering the PDF. Skipped when pwsh is
not installed. The renders use the classic style, which needs no browser, and skip when reportlab is missing.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

SCRIPT = ROOT / "Invoke-RenderReport.ps1"


def _have_pwsh():
    return shutil.which("pwsh") is not None


def _have_reportlab():
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def _bundle(folder):
    from test_delta import ALL_OK
    from test_score import hardened
    b = hardened()
    b["status"] = dict(ALL_OK)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "bundle.json").write_text(json.dumps(b))
    return folder / "bundle.json"


def _run(*args, home=None):
    env = dict(os.environ)
    if home:
        env["HOME"] = str(home)
        env["USERPROFILE"] = str(home)
    return subprocess.run(["pwsh", "-NoProfile", "-File", str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, env=env, timeout=180)


def test_missing_bundle_fails_with_a_plain_message_and_exit_1():
    if not _have_pwsh():
        return
    r = _run("-Bundle", "/definitely/not/here/bundle.json")
    assert r.returncode == 1
    assert "ERROR: Bundle not found" in r.stderr
    assert "at <ScriptBlock>" not in r.stderr and "Line |" not in r.stderr  # no PowerShell stack trace


def test_folder_without_a_bundle_says_so():
    if not _have_pwsh():
        return
    with tempfile.TemporaryDirectory() as tmp:
        r = _run("-Bundle", tmp)
        assert r.returncode == 1 and "No bundle.json in folder" in r.stderr


def test_invalid_style_is_rejected_before_anything_runs():
    if not _have_pwsh():
        return
    with tempfile.TemporaryDirectory() as tmp:
        r = _run("-Bundle", _bundle(Path(tmp) / "ACME"), "-Style", "bogus")
        assert r.returncode != 0 and "brief,classic" in r.stderr
        assert not (Path(tmp) / "ACME" / "report.pdf").exists()


def test_unknown_capability_name_surfaces_the_renderers_message():
    if not (_have_pwsh() and _have_reportlab()):
        return
    with tempfile.TemporaryDirectory() as tmp:
        r = _run("-Bundle", _bundle(Path(tmp) / "ACME"), "-Style", "classic", "-NotLicensed", "bogus")
        assert r.returncode == 1
        assert "unknown bogus" in (r.stdout + r.stderr)


def test_render_writes_the_pdf_and_copies_it_with_outdir_and_outfile():
    if not (_have_pwsh() and _have_reportlab()):
        return
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        folder = tmp / "ACME"
        _bundle(folder)
        r = _run("-Bundle", folder, "-Style", "classic", "-OutDir", tmp / "out")
        assert r.returncode == 0, r.stdout + r.stderr
        assert (folder / "report.pdf").read_bytes().startswith(b"%PDF")
        assert (tmp / "out" / "ACME-report.pdf").read_bytes().startswith(b"%PDF")
        r = _run("-Bundle", folder / "bundle.json", "-Style", "classic", "-OutFile", tmp / "x" / "named.pdf")
        assert r.returncode == 0 and (tmp / "x" / "named.pdf").read_bytes().startswith(b"%PDF")


def test_default_lookup_uses_the_newest_raw_bundle_and_never_the_redacted_one():
    if not (_have_pwsh() and _have_reportlab()):
        return
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        folder = home / "CyberReadiness" / "ACME"
        raw = _bundle(folder)
        (folder / "bundle.redacted.json").write_text(raw.read_text())
        r = _run("-Style", "classic", home=home)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Using newest bundle" in r.stdout and "bundle.redacted.json" not in r.stdout.split("Rendering")[0]
        assert "redacted bundle" not in r.stderr  # no warning: it picked the raw file


def test_redacted_bundle_gets_a_warning_but_still_renders():
    if not (_have_pwsh() and _have_reportlab()):
        return
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "ACME"
        raw = _bundle(folder)
        red = folder / "bundle.redacted.json"
        red.write_text(raw.read_text())
        r = _run("-Bundle", red, "-Style", "classic")
        assert r.returncode == 0 and "redacted bundle" in (r.stdout + r.stderr)
