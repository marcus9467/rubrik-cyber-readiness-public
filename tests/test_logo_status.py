import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import render_html  # noqa: E402


def with_logo(tmp, content):
    old = render_html.ASSETS
    render_html.ASSETS = tmp
    if content is not None:
        (tmp / "rubrik-logo-primary-linear.svg").write_text(content)
    try:
        return render_html.logo_status(), render_html._logo_uri()
    finally:
        render_html.ASSETS = old


def test_missing_logo_says_so_and_falls_back():
    import tempfile
    msg, uri = with_logo(Path(tempfile.mkdtemp()), None)
    assert msg.startswith("logo: not found") and "text mark" in msg and uri is None


def test_valid_svg_is_used():
    import tempfile
    msg, uri = with_logo(Path(tempfile.mkdtemp()), '<svg xmlns="http://www.w3.org/2000/svg"></svg>')
    assert msg.startswith("logo: using") and uri.startswith("data:image/svg+xml;base64,")


def test_non_svg_file_is_reported_and_skipped_not_embedded():
    import tempfile
    msg, uri = with_logo(Path(tempfile.mkdtemp()), "<html>login page</html>")
    assert "not an SVG" in msg and uri is None
