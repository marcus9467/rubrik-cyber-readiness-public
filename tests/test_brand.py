import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import brand  # noqa: E402
import render_html  # noqa: E402


def with_brand(raw=None, text=None):
    d = Path(tempfile.mkdtemp())
    if raw is not None:
        (d / "brand.json").write_text(json.dumps(raw))
    if text is not None:
        (d / "brand.json").write_text(text)
    os.environ["CRR_BRAND_DIR"] = str(d)


def teardown():
    os.environ.pop("CRR_BRAND_DIR", None)


def test_default_is_neutral():
    with_brand()
    try:
        css = render_html._css(None)
        assert "Rubrik" not in css and "security and AI" not in css
        assert "Host Grotesk" not in css and "DM Mono" not in css
        assert "Confidential" in css and "Cyber Readiness" in css
        assert brand.load()["bundled_fonts"] is False and render_html._font_faces() == ""
    finally:
        teardown()


def test_brand_json_overrides_palette_footer_and_mark():
    with_brand({"palette": {"accent": "#112233"}, "footer_left": "Acme  Confidential", "text_mark": "Acme",
                "bundled_fonts": True})
    try:
        css = render_html._css(None)
        assert "#112233" in css and "Acme  Confidential" in css and '"Acme"' in css
        assert "'DM Mono'" in css and render_html._font_faces() != ""
    finally:
        teardown()


def test_bad_values_and_bad_file_fall_back_without_raising():
    with_brand({"palette": {"accent": "teal", "nope": "#000000"}, "footer_left": 5})
    try:
        b = brand.load()
        assert b["palette"]["accent"] == brand.DEFAULTS["palette"]["accent"]
        assert b["footer_left"] == "Confidential" and len(b["warnings"]) == 2
    finally:
        teardown()
    with_brand(text="{not json")
    try:
        b = brand.load()
        assert b["palette"] == brand.DEFAULTS["palette"] and b["warnings"]
    finally:
        teardown()


def test_quotes_and_backslashes_cannot_break_the_css_string():
    with_brand({"footer_left": 'A" } @page { x: "\\B'})
    try:
        css = render_html._css(None)
        assert 'content: "A } @page { x: B"' in css
    finally:
        teardown()


def test_brand_dir_logo_is_found_before_legacy_path():
    with_brand()
    try:
        d = brand.brand_dir()
        (d / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"></svg>')
        assert render_html.logo_status() == f"logo: using {d / 'logo.svg'}"
        assert render_html._logo_uri().startswith("data:image/svg+xml;base64,")
    finally:
        teardown()
