"""print_to_pdf: trust the output file, not Chrome's exit code. A fake Chrome stands in, so no browser is needed."""
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from render_html import _looks_like_pdf, print_to_pdf  # noqa: E402

GOOD = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


def fake_chrome(tmp, body, code):
    """A script that behaves like Chrome: reads the --print-to-pdf= argument, writes body to it, exits with code."""
    script = Path(tmp) / "fake_chrome.py"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "out = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--print-to-pdf='))\n"
        f"body = {body!r}\n"
        "if body is not None:\n"
        "    open(out, 'wb').write(body)\n"
        "sys.stderr.write('CVDisplayLinkCreateWithCGDisplay failed. CVReturn: -6670\\n')\n"
        f"sys.exit({code})\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run(body, code, stale=None):
    with tempfile.TemporaryDirectory() as tmp:
        html, out = Path(tmp) / "r.html", Path(tmp) / "r.pdf"
        html.write_text("<html></html>")
        if stale is not None:
            out.write_bytes(stale)
        try:
            print_to_pdf(html, out, chrome=fake_chrome(tmp, body, code))
            return None, out.exists() and out.read_bytes()
        except SystemExit as e:
            return str(e), out.exists()


def test_nonzero_exit_with_a_good_pdf_is_success():
    err, data = run(GOOD, 2)
    assert err is None and data == GOOD


def test_zero_exit_with_a_good_pdf_is_success():
    err, data = run(GOOD, 0)
    assert err is None and data == GOOD


def test_no_file_written_fails_and_reports_the_exit_code():
    err, exists = run(None, 2)
    assert err and "status 2" in err and "no valid PDF" in err
    assert exists is False


def test_zero_exit_but_no_file_still_fails():
    err, exists = run(None, 0)
    assert err and exists is False


def test_stale_pdf_cannot_mask_a_failed_run():
    err, exists = run(None, 2, stale=GOOD)
    assert err, "an old report.pdf must not make a failed run look successful"
    assert exists is False


def test_truncated_pdf_is_rejected_and_removed():
    err, exists = run(b"%PDF-1.4\n1 0 obj\n<<", 2)
    assert err and exists is False


def test_garbage_file_is_rejected():
    err, exists = run(b"<html>not a pdf</html>", 0)
    assert err and exists is False


def test_error_message_carries_chromes_last_output():
    err, _ = run(None, 2)
    assert "CVDisplayLink" in err


def test_looks_like_pdf():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "x.pdf"
        p.write_bytes(GOOD)
        assert _looks_like_pdf(p)
        p.write_bytes(b"%PDF-1.4 no end")
        assert not _looks_like_pdf(p)
        assert not _looks_like_pdf(Path(tmp) / "missing.pdf")
