"""Report branding. The defaults are neutral. A local, git-ignored brand/ folder overrides them.

brand/brand.json (all keys optional):
  palette          ink, muted, soft, accent, accent2, card_bg, card_line, rule, red, amber  (#RRGGBB)
  footer_left      text in the page footer
  header_right     text in the page header
  text_mark        wordmark shown when there is no logo
  author           PDF author metadata (classic style)
  bundled_fonts    true to embed the OFL fonts in assets/fonts (Host Grotesk, DM Mono)
brand/logo.svg     logo for the brief style
brand/logo.png     logo for the classic style
CRR_BRAND_DIR overrides the folder, for tests and for keeping several brands.
"""
import json
import os
import re
from pathlib import Path

DEFAULTS = {
    "palette": {
        "ink": "#1F2933", "muted": "#6B7280", "soft": "#3E4C59", "accent": "#2F5D8A", "accent2": "#6B5B95",
        "card_bg": "#F5F7FA", "card_line": "#E1E5EA", "rule": "#E1E5EA", "red": "#DA4750", "amber": "#E8A317",
    },
    "footer_left": "Confidential",
    "header_right": "Cyber readiness assessment",
    "text_mark": "Cyber Readiness",
    "author": "",
    "bundled_fonts": False,
    "not_licensed": [],
}
HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")


def brand_dir():
    return Path(os.environ.get("CRR_BRAND_DIR") or Path(__file__).resolve().parent / "brand")


def _text(v, fallback):
    """Plain single-line text. Quotes and backslashes would break the CSS content string."""
    if not isinstance(v, str):
        return fallback
    return re.sub(r"[\\\"\n\r]", "", v).strip()[:120] or fallback


def load():
    """Defaults merged with brand/brand.json. A bad file or a bad value is ignored, never fatal."""
    out = {**DEFAULTS, "palette": dict(DEFAULTS["palette"]), "warnings": []}
    p = brand_dir() / "brand.json"
    if not p.exists():
        return out
    try:
        raw = json.loads(p.read_text())
        assert isinstance(raw, dict)
    except (OSError, ValueError, AssertionError) as e:
        out["warnings"].append(f"{p} ignored: {e}")
        return out
    for k, v in (raw.get("palette") or {}).items():
        if k in out["palette"] and isinstance(v, str) and HEX.match(v):
            out["palette"][k] = v
        else:
            out["warnings"].append(f"palette.{k} ignored: expected one of {sorted(DEFAULTS['palette'])} as #RRGGBB")
    for k in ("footer_left", "header_right", "text_mark", "author"):
        if k in raw:
            out[k] = _text(raw[k], DEFAULTS[k])
    out["bundled_fonts"] = raw.get("bundled_fonts") is True
    nl = raw.get("not_licensed")
    if isinstance(nl, list):
        out["not_licensed"] = [x for x in nl if isinstance(x, str)]
    return out
