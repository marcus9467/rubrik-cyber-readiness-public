"""Render a scored bundle as an HTML brief and print it to PDF with headless Chrome.

Neutral by default; brand.py applies a local palette, footer, logo and fonts. Reference style: technical brief, off-white
cards, numbered sections, mono kickers, header and footer on every page. The reportlab renderer in
render_pdf.py stays available as --style classic.

Needs Google Chrome or Chromium (found automatically, or set CHROME). Fonts ship in assets/; an optional logo SVG is used if present;
without them the page falls back to system sans and a text mark.
"""
import base64
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from html import escape as esc
from pathlib import Path

import brand
import capabilities
import inventory_report
from delta import compute as compute_delta, describe_change
from frameworks import CSF_NAMES
from posture import DOMAIN_SOURCES, domain_rows, overall
from report_text import BUCKET_LABEL, BUCKET_NOTE, METHOD_NOTES, PHASE_TITLE
from roadmap import csf_rows, plan, projections
from score import score

def _find_chrome():
    """CHROME wins; then the usual install paths and PATH names on macOS, Linux and Windows."""
    if os.environ.get("CHROME"):
        return os.environ["CHROME"]
    for p in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"):
        if Path(p).exists():
            return p
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


CHROME = _find_chrome()
ASSETS = Path(__file__).resolve().parent / "assets"

# Palette comes from brand.py: neutral by default, overridden by the local brand/brand.json.
_P = brand.load()["palette"]
INK, MUTED, SOFT = _P["ink"], _P["muted"], _P["soft"]
TEAL, PURPLE = _P["accent"], _P["accent2"]  # names kept; the accent is whatever the brand says
CARD_BG, CARD_LINE, RULE = _P["card_bg"], _P["card_line"], _P["rule"]
RED, AMBER = _P["red"], _P["amber"]
SEV_COLOR = {"critical": RED, "high": RED, "medium": AMBER, "low": MUTED, "info": MUTED}


def _b64(path):
    return base64.b64encode(Path(path).read_bytes()).decode()


def _font_faces():
    if not brand.load()["bundled_fonts"]:
        return ""
    faces = []
    for family, fname, weight in (("Host Grotesk", "HostGrotesk-Regular.ttf", 400),
                                  ("Host Grotesk", "HostGrotesk-SemiBold.ttf", 600),
                                  ("DM Mono", "DMMono-Regular.ttf", 400),
                                  ("DM Mono", "DMMono-Medium.ttf", 500)):
        p = ASSETS / "fonts" / fname
        if p.exists():
            faces.append(f"@font-face{{font-family:'{family}';font-weight:{weight};"
                         f"src:url(data:font/ttf;base64,{_b64(p)}) format('truetype');}}")
    return "\n".join(faces)


def _logo_path():
    for p in (brand.brand_dir() / "logo.svg", ASSETS / "rubrik-logo-primary-linear.svg"):
        if p.exists():
            return p
    return None


def logo_status():
    """One line saying whether the report will carry the logo. The logo is supplied locally and may be absent."""
    p = _logo_path()
    if p is None:
        return f"logo: not found, using the text mark. To brand the report, add {brand.brand_dir() / 'logo.svg'}"
    try:
        head = p.read_text(errors="replace")[:2000]
    except OSError as e:
        return f"logo: {p} could not be read ({e}), using the text mark"
    if "<svg" not in head:
        return f"logo: {p} is not an SVG, using the text mark"
    return f"logo: using {p}"


def _logo_uri():
    """Official linear logo as a data URI with an explicit size (margin boxes use the intrinsic size)."""
    p = _logo_path()
    if p is None or "<svg" not in p.read_text(errors="replace")[:2000]:
        return None
    svg = p.read_text()
    svg = re.sub(r"<svg ", '<svg width="58" height="24" ', svg, count=1)
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


def grade_color(v):
    if v is None:
        return MUTED
    return TEAL if v >= 85 else AMBER if v >= 70 else RED


CSS = """
@page { size: Letter; margin: 0.95in 0.75in 0.9in 0.75in;
  @top-left { content: __LOGO__; vertical-align: bottom; padding-bottom: 7pt; font: 600 10pt __SANS__; color: __INK__; border-bottom: 0.6pt solid __RULE__; width: 50%; }
  @top-right { content: "__HEADER__"; vertical-align: bottom; padding-bottom: 9pt; text-align: right;
    border-bottom: 0.6pt solid __RULE__; width: 50%; font: 500 6.6pt __MONO__; letter-spacing: .16em;
    text-transform: uppercase; color: __MUTED__; }
  @bottom-left { content: "__FOOTER__"; vertical-align: top; padding-top: 9pt;
    border-top: 0.6pt solid __RULE__; font: 500 6.6pt __MONO__; letter-spacing: .16em;
    text-transform: uppercase; color: __MUTED__; width: 75%; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); vertical-align: top; padding-top: 9pt;
    text-align: right; border-top: 0.6pt solid __RULE__; font: 500 6.6pt __MONO__;
    letter-spacing: .16em; text-transform: uppercase; color: __MUTED__; }
}
*{box-sizing:border-box;}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
body{margin:0;font-family:__SANS__;font-weight:400;font-size:9.6pt;
  line-height:1.5;color:__INK__;}
p{margin:0 0 6pt;} b,strong{font-weight:600;}
h1{font-size:31pt;line-height:1.06;font-weight:600;margin:4pt 0 8pt;letter-spacing:-.01em;}
h2{font-size:14.5pt;line-height:1.25;font-weight:600;margin:16pt 0 6pt;break-after:avoid;}
h3{font-size:10.4pt;line-height:1.3;font-weight:600;margin:11pt 0 4pt;break-after:avoid;}
.num{color:__TEAL__;}
.kicker{font:500 7.4pt __MONO__;letter-spacing:.2em;text-transform:uppercase;color:__TEAL__;margin-top:6pt;}
.lede{font-size:12.4pt;line-height:1.42;color:__SOFT__;margin:0 0 4pt;max-width:5.6in;}
.rule{width:56px;height:3px;background:__TEAL__;margin:12pt 0 4pt;}
.small{font-size:7.8pt;line-height:1.4;color:__MUTED__;}
.mono{font-family:__MONO__;}
.pb{break-before:page;}
ul{margin:0 0 7pt;padding-left:13pt;} li{margin:0 0 3pt;}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:7pt;margin:10pt 0 4pt;}
.stat{background:__CARD__;border:1px solid __LINE__;border-radius:8px;padding:8pt 9pt;break-inside:avoid;}
.stat .lab{font-size:7.2pt;line-height:1.3;color:__MUTED__;min-height:19pt;}
.stat .big{font-size:23pt;line-height:1.1;font-weight:600;margin:1pt 0;}
.stat .sub{font-size:6.8pt;line-height:1.3;color:__MUTED__;}
table{border-collapse:collapse;width:100%;margin:2pt 0 8pt;}
th{background:__CARD__;color:__MUTED__;font-weight:400;font-size:7.4pt;text-align:left;padding:5pt 7pt;}
td{padding:4pt 7pt;border-bottom:1px solid __RULE__;font-size:8.5pt;vertical-align:top;}
td.r,th.r{text-align:right;} td.nowrap{white-space:nowrap;}
tr{break-inside:avoid;}
.callout{border-left:3px solid __TEAL__;background:__CARD__;padding:8pt 12pt;border-radius:0 7px 7px 0;
  margin:8pt 0;break-inside:avoid;font-size:9pt;}
.card{border:1px solid __LINE__;border-radius:8px;padding:6pt 10pt;margin:0 0 6pt;break-inside:avoid;}
.bar{height:7px;background:__RULE__;border-radius:4px;overflow:hidden;min-width:120pt;}
.bar i{display:block;height:100%;border-radius:4px;}
.keep{break-inside:avoid;}
.caps{display:grid;grid-template-columns:1fr 1fr;gap:8pt;margin:8pt 0 6pt;}
.cap{border:1px solid __LINE__;border-top:4px solid var(--c);border-radius:8px;padding:9pt 11pt;break-inside:avoid;background:#fff;}
.cap .top{display:flex;justify-content:space-between;align-items:baseline;gap:6pt;}
.cap .nm{font-weight:600;font-size:10.6pt;}
.cap .st{font:500 6.2pt __MONO__;letter-spacing:.12em;text-transform:uppercase;color:var(--c);white-space:nowrap;}
.cap .sc{font-size:34pt;line-height:1;font-weight:600;color:var(--c);margin:5pt 0 1pt;}
.cap .sc small{font-size:9pt;font-weight:400;color:__MUTED__;}
.cap .q{font:500 6.2pt __MONO__;letter-spacing:.14em;text-transform:uppercase;color:__MUTED__;margin-top:5pt;}
.cap .pf{font-size:9pt;font-weight:600;margin:1pt 0 4pt;}
.cap .ev{font-size:8pt;margin:0 0 3pt;color:__SOFT__;}
.cap .cons{font-size:8pt;margin:0;color:__INK__;}
.alarm{border-left:4px solid __RED__;background:#FDF1F2;padding:9pt 13pt;border-radius:0 7px 7px 0;margin:8pt 0;break-inside:avoid;font-size:9.4pt;}
.alarm b{color:__RED__;}
.two{break-inside:avoid;display:grid;grid-template-columns:1.25fr 1fr;gap:16pt;align-items:start;}
.chip{display:inline-block;font:500 6.2pt __MONO__;letter-spacing:.1em;text-transform:uppercase;
  color:#fff;padding:2pt 0;border-radius:4px;white-space:nowrap;width:44pt;text-align:center;}
.fh{display:flex;align-items:center;gap:8pt;}
.fh .t{font-weight:600;font-size:10pt;flex:1;line-height:1.3;}
.fh .id{color:__TEAL__;}
.bk{font:500 6.2pt __MONO__;letter-spacing:.12em;text-transform:uppercase;color:__MUTED__;white-space:nowrap;}
.ev{margin:4pt 0 0;font-size:8.8pt;}
.fix{margin:5pt 0 0;font-size:6.8pt;font:500 6.6pt __MONO__;letter-spacing:.14em;text-transform:uppercase;color:__TEAL__;}
ol.steps{margin:2pt 0 3pt;padding-left:14pt;font-size:8.6pt;} ol.steps li{margin:0 0 2pt;}
.docs,.fw{font-size:7.4pt;color:__MUTED__;margin:3pt 0 0;} .docs a{color:__TEAL__;text-decoration:none;}
.fw{font-family:__MONO__;font-size:6.6pt;letter-spacing:.04em;}
.phase li{list-style:none;margin:0 0 2pt;} .phase ul{padding-left:0;}
.id-b{font-weight:600;color:__TEAL__;}
"""


def _css(logo):
    b = brand.load()
    p = b["palette"]
    css = CSS.replace("__LOGO__", f'url("{logo}")' if logo else f'"{b["text_mark"]}"')
    css = css.replace("__FOOTER__", b["footer_left"]).replace("__HEADER__", b["header_right"])
    if b["bundled_fonts"]:
        sans, mono = "'Host Grotesk','Helvetica Neue',Arial,sans-serif", "'DM Mono', monospace"
    else:
        sans = "'Helvetica Neue',Arial,sans-serif"
        mono = "ui-monospace,Menlo,Consolas,monospace"
    css = css.replace("__SANS__", sans).replace("__MONO__", mono)
    for k, v in (("INK", p["ink"]), ("MUTED", p["muted"]), ("SOFT", p["soft"]), ("TEAL", p["accent"]),
                 ("CARD", p["card_bg"]), ("LINE", p["card_line"]), ("RULE", p["rule"]), ("RED", p["red"])):
        css = css.replace(f"__{k}__", v)
    return css


def stat(label, big, sub, color=INK):
    return (f'<div class="stat"><div class="lab">{esc(label)}</div>'
            f'<div class="big" style="color:{color}">{esc(str(big))}</div><div class="sub">{esc(sub)}</div></div>')


def capability_stat(caps):
    """Summary tile: how many capabilities are fully covered, and which ones are not, so it ties to Section 1."""
    groups = capabilities.summary(caps)
    live = sum(len(v) for v in groups.values())
    if not live:
        return stat("Detection capabilities", "n/a", "none assessed")
    gaps = [(label, groups[k]) for k, label in (("blind", "No data"), ("off", "Off"), ("partial", "Partial"))
            if groups[k]]
    sub = "; ".join(f"{label}: {', '.join(names)}" for label, names in gaps) or "all fully covered"
    colour = RED if groups["blind"] or groups["off"] else AMBER if groups["partial"] else TEAL
    return stat("Detection capabilities fully active", f"{len(groups['active'])} of {live}", sub, colour)


def bar(v):
    if v is None:
        return '<span class="small">not assessed</span>'
    return f'<div class="bar"><i style="width:{max(2, v)}%;background:{grade_color(v)}"></i></div>'


def chip(sev):
    return f'<span class="chip" style="background:{SEV_COLOR[sev]}">{esc(sev)}</span>'


def finding(f, compact=False):
    h = [f'<div class="card"><div class="fh">{chip(f["severity"])}'
         f'<div class="t"><span class="id">{esc(f["id"])}</span>&nbsp;&nbsp;{esc(f["title"])}</div>'
         f'<div class="bk">{esc(BUCKET_LABEL[f["bucket"]])}</div></div>'
         f'<p class="ev">{esc(f["evidence"])}</p>']
    if not compact:
        if f.get("steps"):
            h.append('<div class="fix">How to fix</div><ol class="steps">'
                     + "".join(f"<li>{esc(s)}</li>" for s in f["steps"]) + "</ol>")
        else:
            h.append(f'<p class="ev">Recommended: {esc(f["remediation"])}</p>')
        if f.get("docs"):
            links = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(f'<a href="{esc(u)}">{esc(t)}</a>' for t, u in f["docs"])
            h.append(f'<div class="docs">Docs:&nbsp;&nbsp;{links}</div>')
        fw = f.get("framework") or {}
        if fw.get("csf"):
            line = f"NIST CSF: {CSF_NAMES[fw['csf']]}"
            if fw.get("hipaa"):
                line += "  |  HIPAA: " + ", ".join(fw["hipaa"])
            h.append(f'<div class="fw">{esc(line)}</div>')
    h.append("</div>")
    return "".join(h)


def cover(result, rows, ov, findings, proj, collected):
    c = result["counts"]
    assessed = sum(s is not None for _, s in rows)
    fix_now = sum(f["bucket"] == "fix_now" for f in findings)
    d30 = next((v for label, v in proj if label == "After 30 days"), None)
    month = collected.strftime("%B %Y")
    out = [f'<div class="kicker">Cyber readiness assessment &nbsp;&middot;&nbsp; {esc(month)}</div>',
           "<h1>Cyber Readiness<br>Assessment</h1>",
           f'<p class="lede">Where {esc(result["customer"])} stands today across backup, recovery and access, '
           f"what to fix first, and what we measured in {assessed} areas.</p>",
           '<div class="rule"></div>',
           "<h2>Purpose</h2>",
           "<p>This assessment reads the Rubrik Security Cloud configuration and inventory through a read-only "
           "service account and turns it into a ranked list of gaps. Each gap has the evidence behind it, the "
           "steps to close it, and a place in a 30, 60 and 90 day plan.</p>",
           "<h2>What we did</h2><ul>",
           f"<li>Collected data from RSC on {esc(collected.strftime('%B %d, %Y'))} with read-only queries. "
           f"{len(result['collector_status'])} collectors ran; any that failed are shown as not assessed, "
           "never as clean.</li>",
           f"<li>Scored {len(findings)} findings across {assessed} areas and grouped them by what kind of "
           "fix they need.</li>",
           "<li>Tagged each finding with a NIST CSF function and HIPAA Security Rule sections, as a guide "
           "for the conversation and not a statement of compliance.</li></ul>",
           '<div class="stats">',
           stat("Posture score", "n/a" if ov is None else ov, f"average of {assessed} assessed areas",
                grade_color(ov)),
           stat("Findings", len(findings), f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
                f"{c['low']} low"),
           capability_stat(result.get("capabilities") or {}),
           stat("Score after 30 days", "n/a" if d30 is None else d30, "if the 30 day items are resolved"),
           "</div>",
           "<h2>How this document is organized</h2>",
           "<p><b>Section 1.</b> Are you prepared: the detection capabilities that decide whether you "
           "can see an attack, size it and recover cleanly.</p>",
           "<p><b>Section 2.</b> Where you stand: scores by area, the findings that matter most, and what to "
           "do first.</p>",
           "<p><b>Section 3.</b> The roadmap: a projected score, the NIST CSF view and the 30, 60 and 90 day "
           "plan.</p>",
           "<p><b>Appendix.</b> Every finding with its evidence, steps, documentation and framework tags, then "
           "the method and its limits.</p>"]
    return "".join(out)


def prepared_for(result):
    """The four detection capabilities as cards. A capability with no data is a big red zero, not a grey blank."""
    caps = result.get("capabilities") or {}
    live = [c for c in caps.values() if c["score"] is not None]
    if not live:
        return ""
    dark = [d for d, c in caps.items() if c["score"] == 0]
    low = [d for d, c in caps.items() if c["score"] is not None and 0 < c["score"] < 100]
    colour = {"active": TEAL, "partial": AMBER, "off": RED, "blind": RED}
    if dark:
        names = ", ".join(dark[:-1]) + (" and " if len(dark) > 1 else "") + dark[-1]
        headline = (f'<div class="alarm"><b>{len(dark)} of {len(live)} detection capabilities returned nothing.</b> '
                    f"There is no data in RSC for {esc(names)}. In an attack, those are the questions your team "
                    "would not be able to answer: what is being encrypted, what is already hiding in the backups, "
                    "what the attacker touched, and what data was exposed.</div>")
    elif low:
        headline = (f"<div class='callout'><b>{len(low)} of {len(live)} detection capabilities cover only part of "
                    "the estate.</b> Anything outside that coverage is invisible to the team during an "
                    "incident.</div>")
    else:
        headline = (f"<div class='callout'><b>All {len(live)} assessed detection capabilities are active.</b> "
                    "Coverage is complete everywhere RSC reports on it.</div>")
    cards = []
    for dom in capabilities.DOMAINS:
        c = caps.get(dom)
        if c is None or c["score"] is None:
            continue
        col = colour[c["state"]]
        ok = c["state"] == "active"
        cards.append(
            f'<div class="cap" style="--c:{col}"><div class="top"><span class="nm">{esc(dom)}</span>'
            f'<span class="st">{esc(capabilities.STATE_LABEL[c["state"]])}</span></div>'
            f'<div class="sc">{c["score"]}<small> / 100</small></div>'
            f'<div class="q">Are you prepared for</div><div class="pf">{esc(capabilities.PREPARED_FOR[dom])}?</div>'
            f'<p class="ev">{esc(c["evidence"])}</p>'
            + (f'<p class="ev"><b>Why no data:</b> {esc(c["reason"])}</p>' if c.get("reason") else "")
            + ("" if ok else f'<p class="cons">{esc(capabilities.consequence(dom, c["state"]))}</p>') + "</div>")
    note = ""
    if any(c["state"] == "blind" for c in caps.values()):
        note = f'<p class="small">{esc(capabilities.BLIND_NOTE)}</p>'
    skipped = result.get("not_licensed") or []
    skip_note = ""
    if skipped:
        skip_note = '<p class="small">Not assessed, not part of this licence: ' + esc(", ".join(skipped)) + ".</p>"
    intro = (f"<p>{len(caps)} capabilities decide whether your team can see an attack, size it and recover from "
             "it cleanly. Each is scored by what RSC can actually show for your tenant. A capability with no "
             "data scores zero.</p>")
    card_html = '<div class="caps">' + "".join(cards) + "</div>"
    return '<h2 class="pb"><span class="num">1.</span> Are you prepared?</h2>' + intro + headline + card_html + note + skip_note


def where_you_stand(result, rows, findings):
    labels = {"DATA_SAFETY_SCORE": "Data safety (overall)", "SECURITY_CONFIG": "Security configuration",
              "RECOVERABILITY_STATUS": "Recoverability", "ANOMALIES_DETECTED": "Anomaly detection",
              "SENSITIVE_DATA": "Sensitive data"}
    s = result["rsc_scores"]
    area = "".join(f'<tr><td><b>{esc(d)}</b></td><td>{bar(v)}</td><td class="r"><b>'
                   f'{"n/a" if v is None else v}</b></td></tr>'
                   for d, v in rows if d not in set(result.get("not_licensed") or []))
    rsc = ("".join(f'<tr><td>{esc(labels[k])}</td><td class="r"><b>{s[k]:g}</b></td></tr>'
                   for k in labels if k in s)
           if s else '<tr><td class="small">Not available on this tenant.</td></tr>')
    excluded = set(result.get("not_licensed") or [])
    unassessed = [d for d, v in rows if v is None and d not in excluded]
    note = (f'<div class="callout"><b>Not assessed:</b> {esc(", ".join(unassessed))}. Data collection failed '
            "for these areas, so they carry no score.</div>") if unassessed else ""
    if excluded:
        note += ('<p class="small">Left out of scoring, not part of this licence: '
                 + esc(", ".join(sorted(excluded))) + ".</p>")
    top = [f for f in findings if f["severity"] in ("critical", "high")][:3] or findings[:3]
    out = [f'<h2 class="pb"><span class="num">2.</span> Where you stand</h2>',
           f"<p>{len(findings)} findings across {sum(v is not None for _, v in rows)} assessed areas. Scores "
           "start at 100 per area and lose points for each finding, so they show relative gaps and not a "
           "benchmark.</p>", note,
           '<div class="two"><div><table><tr><th>Area</th><th>Score</th><th class="r"></th></tr>'
           f"{area}</table></div>"
           f'<div><h3 style="margin-top:2pt">RSC\'s own resilience scores</h3><table>{rsc}</table>'
           '<p class="small">RSC computes these itself. Their object counts differ from the per-object counts '
           "in this report and the difference has not been reconciled.</p></div></div>",
           "<h3>Priority findings</h3>"]
    out += [finding(f, compact=True) for f in top]
    return "".join(out)


def do_first(findings):
    rows = []
    for b in ("visibility", "fix_now", "process", "enterprise", "unconfirmed"):
        items = [f for f in findings if f["bucket"] == b and f["severity"] != "info"]
        if items:
            rows.append(f"<tr><td class='nowrap'><b>{esc(BUCKET_LABEL[b])}</b></td><td class='r'>{len(items)}</td>"
                        f"<td>{esc(BUCKET_NOTE[b])}</td><td class='mono small'>"
                        + esc(", ".join(f["id"] for f in items)) + "</td></tr>")
    has_unconfirmed = any(f["bucket"] == "unconfirmed" for f in findings)
    has_ee = any(f["bucket"] == "enterprise" for f in findings)
    note = ""
    if has_unconfirmed and not has_ee:
        note = ('<div class="callout"><b>No finding here is presented as an Enterprise Edition benefit.</b> '
                "Where a capability may depend on licensing, the entitlement has not been confirmed, so the "
                "finding is grouped as Edition unconfirmed until it is checked.</div>")
    return ("<div class='keep'><h2>What to do first</h2><table><tr><th>Group</th><th class='r'>Count</th>"
            f"<th>Meaning</th><th>Findings</th></tr>{''.join(rows)}</table>{note}</div>")


def roadmap(findings, rows, caps=None):
    assessed = [d for d, v in rows if v is not None]
    proj = projections(findings, assessed, caps)
    pr = "".join(f"<tr><td>{esc(l)}</td><td class='r'><b>{'n/a' if v is None else v}</b></td></tr>" for l, v in proj)
    sev = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", None: "None"}
    cs = "".join(f"<tr><td>{esc(n)}</td><td class='r'><b>{c}</b></td><td>{sev[w]}</td></tr>"
                 for n, c, w in csf_rows(findings))
    out = ['<h2><span class="num">3.</span> Roadmap</h2>',
           "<p>What to do and when. The phases order the work; they are not commitments.</p>",
           '<div class="two"><div><h3 style="margin-top:2pt">Projected posture score</h3>'
           f"<table>{pr}</table></div><div><h3 style=\"margin-top:2pt\">By NIST CSF function</h3>"
           f"<table><tr><th>Function</th><th class='r'>Findings</th><th>Worst</th></tr>{cs}</table></div></div>",
           '<p class="small">The projection assumes every finding in earlier phases is fully resolved and nothing '
           "new appears. A detection capability keeps its current score until the finding that closes the gap is "
           "resolved. The CSF and HIPAA mapping is the author's judgment, not reviewed by compliance, and not a "
           "statement of compliance.</p>"]
    p = plan(findings)
    for key in (30, 60, 90, "decide"):
        if not p[key]:
            continue
        out.append(f'<h3>{esc(PHASE_TITLE[key])} <span class="small">({len(p[key])})</span></h3>'
                   '<table>' + "".join(
                       f"<tr><td class='nowrap id-b' style='width:48pt'>{esc(f['id'])}</td><td>{esc(f['title'])}</td>"
                       f"<td class='r'>{chip(f['severity'])}</td></tr>" for f in p[key]) + "</table>")
    return "".join(out)


def progress(d):
    o = d["overall"]
    delta = "" if o["before"] is None or o["after"] is None else f" ({o['after'] - o['before']:+d})"
    out = ['<h2 class="pb"><span class="num">4.</span> Progress since last run</h2>',
           f"<p>Previous run {esc(d['before_at'][:10])}, this run {esc(d['after_at'][:10])}. Both runs are "
           "scored with the current rules, and only areas assessed in both runs are compared.</p>",
           f"<div class='callout'><b>Posture score, like for like:</b> {o['before']} to {o['after']}{delta}</div>"]
    if d["domains"]:
        out.append("<table><tr><th>Area</th><th class='r'>Before</th><th class='r'>After</th></tr>" + "".join(
            f"<tr><td>{esc(k)}</td><td class='r'>{v['before']}</td><td class='r'><b>{v['after']}</b></td></tr>"
            for k, v in d["domains"].items()) + "</table>")

    def block(title, items, fmt):
        if items:
            out.append(f"<h3>{esc(title)} <span class='small'>({len(items)})</span></h3><ul>"
                       + "".join(f"<li>{fmt(i)}</li>" for i in items) + "</ul>")

    line = lambda f: f"<span class='id-b'>{esc(f['id'])}</span>&nbsp;&nbsp;{esc(f['title'])}"
    block("Resolved", d["resolved"], line)
    block("New since last run", d["new"], line)
    sev = lambda p: (f"<span class='id-b'>{esc(p[0]['id'])}</span>&nbsp;&nbsp;{esc(p[0]['severity'])} to "
                     f"{esc(p[1]['severity'])}")
    block("Severity improved", d["improved"], sev)
    block("Severity worse", d["worse"], sev)
    block("Still open, numbers changed", d["moved"],
          lambda p: f"<span class='id-b'>{esc(p[0]['id'])}</span>&nbsp;&nbsp;{esc(describe_change(p[0], p[1]))}")
    out.append(f"<p class='small'>{d['unchanged']} findings are unchanged.</p>")
    if d["not_comparable"]:
        out.append("<p class='small'>Not compared (not assessed in both runs): "
                   + esc(", ".join(d["not_comparable"])) + ".</p>")
    return "".join(out)


def estate_summary(data):
    """One callout for the scorecard page: cluster count, versions and how many clusters archive to RCV."""
    s = inventory_report.summary(data)
    if not s:
        return ""
    vers = ", ".join(f"{v} ({n})" for v, n in sorted(s["versions"].items(), reverse=True))
    if s["rcvKnown"]:
        rcv = (f"{s['toRcv']} of {s['clusters']} clusters archive to Rubrik Cloud Vault and "
               f"{s['notToRcv']} do not.")
    else:
        rcv = ("Whether each cluster archives to Rubrik Cloud Vault is not known, because this data was collected "
               "before cluster ids were recorded on archive targets.")
    eos = (f" End-of-support status was not reported for {s['eosUnknown']} of them." if s["eosUnknown"] else "")
    return (f'<div class="callout"><b>Your estate:</b> {s["clusters"]} clusters ({s["connected"]} connected). '
            f"Software versions: {esc(vers)}. {rcv}{eos} The full list is in the appendix.</div>")


def cluster_inventory(data):
    """Appendix table: every cluster with version, status, end-of-support and RCV."""
    rows = inventory_report.cluster_rows(data)
    if not rows:
        return ""
    known = inventory_report.rcv_known(data)

    def rcv_cell(r):
        if not known:
            return "Not known"
        return f"Yes, {r['rcvSlas']} SLA{'s' if r['rcvSlas'] != 1 else ''}" if r["toRcv"] else "No"

    def eos_cell(r):
        e = r["eos"]
        date = f"<br><span class='small nowrap'>{esc(e['date'])}</span>" if e["date"] else ""
        return esc(e["label"]) + date

    def objects_cell(r):
        return format(r["objectsUnderRcvSlas"], ",") if known else "n/a"

    body = "".join(
        f"<tr><td>{esc(r['name'] or r['id'])}</td><td class='mono small'>{esc(r['version'] or 'unknown')}</td>"
        f"<td>{esc(r['status'] or 'unknown')}</td><td>{eos_cell(r)}</td><td>{esc(rcv_cell(r))}</td>"
        f"<td class='r'>{objects_cell(r)}</td></tr>"
        for r in rows)
    return ('<h2 class="pb">Appendix. Cluster inventory</h2>'
            "<p>Every Rubrik cluster RSC reports, with its software version and whether it archives to Rubrik Cloud "
            "Vault (RCV).</p>"
            "<table><tr><th>Cluster</th><th>Version</th><th>Status</th><th>End of support</th><th>Archives to RCV</th>"
            f"<th class='r'>Objects under RCV SLAs</th></tr>{body}</table>"
            "<p class='small'>Objects under RCV SLAs counts active protected objects under SLAs that archive from "
            "that cluster to RCV. An SLA can span several clusters, so this is an upper bound on what one cluster "
            "sends. RCV is identified by archival location type, not by name. End of support shows Not reported when "
            "RSC returns no support information, which is not the same as supported.</p>")


def appendix(result, findings):
    out = ['<h2 class="pb">Appendix. Technical findings</h2>',
           "<p>Every finding with its evidence and recommended action, grouped by area.</p>"]
    by = {}
    for f in findings:
        by.setdefault(f["domain"], []).append(f)
    for dom in DOMAIN_SOURCES:
        if dom in by:
            out.append(f"<h3>{esc(dom)}</h3>")
            out += [finding(f) for f in by[dom]]
    out.append('<h2 class="pb">Method and limits</h2><ul>' + "".join(f"<li>{esc(n)}</li>" for n in METHOD_NOTES)
               + "</ul><h3>Collector status</h3><table>"
               + "".join(f"<tr><td style='width:90pt'>{esc(k)}</td><td>{esc(v if v == 'ok' else v[:90])}</td></tr>"
                         for k, v in result["collector_status"].items()) + "</table>")
    if result["skipped_rules"]:
        out.append("<p class='small'>Rules that could not run: "
                   + esc(", ".join(s["rule"] for s in result["skipped_rules"])) + ".</p>")
    return "".join(out)


def build_html(bundle, previous=None):
    result = score(bundle, brand.load()["not_licensed"])
    rows = domain_rows(result, bundle["data"])
    ov = overall(rows)
    findings = result["findings"]
    collected = datetime.fromisoformat(result["collected_at"])
    caps = result.get("capabilities")
    proj = projections(findings, [d for d, v in rows if v is not None], caps)
    body = [cover(result, rows, ov, findings, proj, collected), prepared_for(result),
            where_you_stand(result, rows, findings) + estate_summary(bundle["data"]),
            do_first(findings), roadmap(findings, rows, caps)]
    if previous is not None:
        body.append(progress(compute_delta(previous, bundle)))
    body.append(cluster_inventory(bundle["data"]))
    body.append(appendix(result, findings))
    title = f"Cyber Readiness Assessment - {result['customer']}"
    html = (f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(title)}</title>"
            f"<style>{_font_faces()}\n{_css(_logo_uri())}</style></head><body>{''.join(body)}</body></html>")
    return html, result


def _looks_like_pdf(path):
    """True if the file starts with the PDF header and ends with the EOF marker, so it is not truncated."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return False
    return raw[:5] == b"%PDF-" and b"%%EOF" in raw[-1024:]


def print_to_pdf(html_path, out_path, chrome=None, timeout=180):
    """Print html_path to out_path with headless Chrome.

    Chrome on macOS often exits nonzero (display link and task policy warnings) after writing a good PDF,
    so the exit code is not trusted. The output file is: any old file is removed first so a stale PDF can
    never pass, and the new one must have a PDF header and an EOF marker.
    """
    chrome = chrome or CHROME
    html_path, out_path = Path(html_path), Path(out_path)
    out_path.unlink(missing_ok=True)
    profile = tempfile.mkdtemp()  # own profile, so a running Chrome cannot swallow the job
    cmd = [chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--user-data-dir={profile}",
           f"--print-to-pdf={out_path}", html_path.resolve().as_uri()]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        out_path.unlink(missing_ok=True)  # a partial file must not be left looking finished
        raise SystemExit(f"Chrome did not finish within {timeout} seconds and no PDF was kept.")
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    if not _looks_like_pdf(out_path):
        out_path.unlink(missing_ok=True)
        tail = " ".join((proc.stderr or "").split())[-400:]
        raise SystemExit(f"Chrome exited with status {proc.returncode} and wrote no valid PDF."
                         + (f" Last output: {tail}" if tail else ""))


def build(bundle, out_path, previous=None):
    """Write report.html next to out_path and print it to out_path with headless Chrome."""
    if not Path(CHROME).exists():
        raise SystemExit(f"Chrome not found at {CHROME}. Set CHROME, or use --style classic.")
    print(logo_status())
    html, result = build_html(bundle, previous)
    out_path = Path(out_path)
    html_path = out_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    print_to_pdf(html_path, out_path)
    return result
