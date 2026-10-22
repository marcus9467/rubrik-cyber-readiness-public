"""Render a scored bundle as a PDF: executive summary first, technical appendix after.

Usage: python3 render_pdf.py --bundle ~/.local/share/cyber-readiness/<customer>/bundle.json [--style classic]
Writes report.pdf next to the bundle. The default style prints HTML with Chrome (render_html.py);
--style classic uses reportlab and needs no browser.
"""
import argparse
import json
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import brand
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from delta import compute as compute_delta, describe_change
from frameworks import CSF_NAMES
from posture import DOMAIN_SOURCES, domain_rows, overall
from report_text import BUCKET_LABEL, BUCKET_NOTE, PHASE_TITLE
from roadmap import csf_rows, plan, projections
from score import score

# Brand v1.1 tokens
_B = brand.load()
_P = _B["palette"]
INK = HexColor(_P["ink"])
OFF_WHITE = HexColor(_P["card_bg"])
TEAL = HexColor(_P["accent"])  # name kept; the accent is whatever the brand says
TEAL_TINT = HexColor(_P["card_bg"])
RED = HexColor(_P["red"])
AMBER = HexColor(_P["amber"])
MID_GRAY = HexColor(_P["muted"])
RULE = HexColor(_P["rule"])

def _logo_png():
    for p in (brand.brand_dir() / "logo.png", Path(__file__).resolve().parent / "assets" / "rubrik-logo.png"):
        if p.exists():
            return p
    return None


LOGO = _logo_png()


def logo_status():
    if LOGO:
        return f"logo: using {LOGO}"
    return f"logo: not found, using the text mark. To brand the classic report, add {brand.brand_dir() / 'logo.png'}"

SEV_COLOR = {"critical": RED, "high": RED, "medium": AMBER, "low": MID_GRAY, "info": MID_GRAY}
TAG_LABEL = {
    "fix_now": "Fix now",
    "ee_candidate": "Edition unconfirmed",
    "process": "Process",
}
TAG_NOTE = {
    "fix_now": "Configurable today.",
    "ee_candidate": "May depend on edition or licensing; confirm before relying on it.",
    "process": "Needs a runbook, owner or decision.",
}
H1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=INK, spaceAfter=4)
H2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=TEAL,
                    spaceBefore=12, spaceAfter=5, keepWithNext=1)
H3 = ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=INK, spaceAfter=2)
BODY = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13, textColor=INK)
SMALL = ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=10.5, textColor=MID_GRAY)
CELL = ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5, leading=11, textColor=INK)
CELL_B = ParagraphStyle("cellb", parent=CELL, fontName="Helvetica-Bold")
H3S = ParagraphStyle("h3s", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=TEAL, spaceBefore=3)
CELL_IND = ParagraphStyle("cellind", parent=CELL, leftIndent=12, firstLineIndent=-12)
DOCS = ParagraphStyle("docs", fontName="Helvetica", fontSize=8, leading=10.5, textColor=MID_GRAY, spaceBefore=2)
CHIP = ParagraphStyle("chip", fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=white, alignment=1)


def P(text, style=BODY):
    return Paragraph(escape(str(text)), style)


def grade_color(score_value):
    if score_value is None:
        return MID_GRAY
    return TEAL if score_value >= 85 else AMBER if score_value >= 70 else RED


def score_bar(score_value, width=2.3 * inch):
    """Two-cell table that draws a proportional bar."""
    if score_value is None:
        return P("not assessed", SMALL)
    fill = max(0.02, score_value / 100) * width
    t = Table([["", ""]], colWidths=[fill, width - fill], rowHeights=[8])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), grade_color(score_value)),
                           ("BACKGROUND", (1, 0), (1, 0), RULE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return t


def chip(text, color):
    t = Table([[Paragraph(escape(text.upper()), CHIP)]], colWidths=[0.62 * inch], rowHeights=[13])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
                           ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    return t


def header_block(result, overall_score):
    # The brandmark PNG is square (256x256); never stretch it.
    logo = Image(str(LOGO), width=0.5 * inch, height=0.5 * inch, hAlign="LEFT") if LOGO else P(_B["text_mark"], H3)
    date = datetime.fromisoformat(result["collected_at"]).strftime("%B %d, %Y")
    left = [logo, Spacer(1, 6), P("Cyber Readiness Assessment", H1),
            P(f"{result['customer']}  |  data collected {date}", SMALL)]
    big = Paragraph(f'<font size="34" color="{grade_color(overall_score).hexval()}"><b>'
                    f'{overall_score if overall_score is not None else "n/a"}</b></font>'
                    f'<font size="11" color="{MID_GRAY.hexval()}"> / 100</font>',
                    ParagraphStyle("big", leading=40, alignment=2))
    right = [big, P("Posture score (average of assessed domains)", ParagraphStyle("c", parent=SMALL, alignment=2))]
    t = Table([[left, right]], colWidths=[4.6 * inch, 2.4 * inch])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("LINEBELOW", (0, 0), (-1, 0), 1.2, TEAL),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    return t


def scorecard(rows):
    data = [[P(d, CELL_B), score_bar(s), P("n/a" if s is None else s, CELL_B)] for d, s in rows]
    t = Table(data, colWidths=[1.3 * inch, 2.5 * inch, 0.5 * inch])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def severity_counts(result):
    c = result["counts"]
    cells = []
    for sev in ("critical", "high", "medium", "low"):
        cells.append([Paragraph(f'<font size="18" color="{SEV_COLOR[sev].hexval()}"><b>{c[sev]}</b></font>',
                                ParagraphStyle("n", alignment=1, leading=22)),
                      P(sev.capitalize(), ParagraphStyle("l", parent=SMALL, alignment=1))])
    t = Table([[x[0] for x in cells], [x[1] for x in cells]], colWidths=[0.8 * inch] * 4)
    t.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    return t


def finding_parts(f, compact=False):
    head = Table([[chip(f["severity"], SEV_COLOR[f["severity"]]),
                   P(f"{f['id']}  {f['title']}", H3),
                   P(BUCKET_LABEL[f["bucket"]], ParagraphStyle("t", parent=SMALL, alignment=2))]],
                 colWidths=[0.7 * inch, 5.0 * inch, 1.3 * inch])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    parts = [head, P(f["evidence"], CELL)]
    if not compact:
        if f.get("steps"):
            parts.append(P("How to fix", H3S))
            parts.extend(Paragraph(f"{i}.&nbsp;&nbsp;{escape(s)}", CELL_IND) for i, s in enumerate(f["steps"], 1))
        else:
            parts.append(P("Recommended: " + f["remediation"], CELL))
        if f.get("docs"):
            links = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(
                f'<link href="{escape(u)}" color="{TEAL.hexval()}">{escape(t)}</link>' for t, u in f["docs"])
            parts.append(Paragraph("Docs:&nbsp;&nbsp;" + links, DOCS))
        fw = f.get("framework") or {}
        if fw.get("csf"):
            tag = f"NIST CSF: {CSF_NAMES[fw['csf']]}"
            if fw.get("hipaa"):
                tag += "&nbsp;&nbsp;|&nbsp;&nbsp;HIPAA: " + ", ".join(fw["hipaa"])
            parts.append(Paragraph(tag, DOCS))
    parts.append(Spacer(1, 8))
    return parts


def finding_card(f, compact=False):
    return KeepTogether(finding_parts(f, compact))


def rsc_scores_table(result):
    labels = {"DATA_SAFETY_SCORE": "Data safety (overall)", "SECURITY_CONFIG": "Security configuration",
              "RECOVERABILITY_STATUS": "Recoverability", "ANOMALIES_DETECTED": "Anomaly detection",
              "SENSITIVE_DATA": "Sensitive data"}
    s = result["rsc_scores"]
    if not s:
        return None
    rows = [[P(labels[k], CELL), P(f"{s[k]:g}", CELL_B)] for k in labels if k in s]
    t = Table(rows, colWidths=[2.2 * inch, 0.6 * inch])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(0.75 * inch, 0.5 * inch, f"Cyber Readiness Assessment  |  {_B['footer_left']}")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


def roadmap_page(findings, rows):
    assessed = [d for d, s in rows if s is not None]
    parts = [P("Roadmap", H1),
             P("What to do and when. Dates are guidance for ordering the work, not commitments.", SMALL)]

    proj = projections(findings, assessed)
    t = Table([[P(label, CELL), P("n/a" if v is None else str(v), CELL_B)] for label, v in proj],
              colWidths=[1.6 * inch, 0.6 * inch])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    proj_cell = [P("Projected posture score", H2), t]

    p = plan(findings)
    for key in (30, 60, 90, "decide"):
        items = p[key]
        if not items:
            continue
        parts.append(P(f"{PHASE_TITLE[key]}  ({len(items)})", H2))
        for f in items:
            parts.append(Paragraph(f"<b>{f['id']}</b>&nbsp;&nbsp;{escape(f['title'])}", CELL))
        parts.append(Spacer(1, 3))

    cr = csf_rows(findings)
    ct = Table([[P(n, CELL), P(str(c), CELL_B), P(w.capitalize() if w else "None", CELL)] for n, c, w in cr],
               colWidths=[1.0 * inch, 0.4 * inch, 0.8 * inch])
    ct.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    side = Table([[proj_cell, [P("By NIST CSF function", H2), ct]]], colWidths=[3.4 * inch, 3.6 * inch])
    side.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    parts.insert(2, side)
    parts.insert(3, P("Projection assumes every finding in earlier phases is fully resolved and nothing new "
                      "appears. Findings that depend on licensing are not assumed fixed, so it does not depend "
                      "on an upgrade. CSF counts are findings and worst severity per function. The CSF and "
                      "HIPAA mapping is the author's judgment, not reviewed by compliance, and not a statement "
                      "of compliance.", SMALL))
    return parts


def progress_page(d):
    """One page: what changed since the previous run. Only domains assessed in both runs are compared."""
    o = d["overall"]
    sign = "" if o["before"] is None or o["after"] is None else f"  ({o['after'] - o['before']:+d})"
    parts = [P("Progress since last run", H1),
             P(f"Previous run {d['before_at'][:10]}, this run {d['after_at'][:10]}. Both runs are scored with the "
               f"current rules, and only areas assessed in both runs are compared.", SMALL),
             P(f"Posture score, like for like: {o['before']} to {o['after']}{sign}", H2)]

    rows = [[P(dom, CELL), P(str(v["before"]), CELL), P(str(v["after"]), CELL_B)] for dom, v in d["domains"].items()]
    if rows:
        t = Table([[P("Area", CELL_B), P("Before", CELL_B), P("After", CELL_B)]] + rows,
                  colWidths=[1.6 * inch, 0.7 * inch, 0.7 * inch])
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        parts.append(t)

    def block(title, items, fmt):
        if not items:
            return
        parts.append(P(f"{title}  ({len(items)})", H2))
        parts.extend(Paragraph(fmt(i), CELL) for i in items)

    f_line = lambda f: f"<b>{f['id']}</b>&nbsp;&nbsp;{escape(f['title'])}"
    block("Resolved", d["resolved"], f_line)
    block("New since last run", d["new"], f_line)
    block("Severity improved", d["improved"], lambda p: f"<b>{p[0]['id']}</b>&nbsp;&nbsp;{p[0]['severity']} to {p[1]['severity']}")
    block("Severity worse", d["worse"], lambda p: f"<b>{p[0]['id']}</b>&nbsp;&nbsp;{p[0]['severity']} to {p[1]['severity']}")
    block("Still open, numbers changed", d["moved"],
          lambda p: f"<b>{p[0]['id']}</b>&nbsp;&nbsp;" + escape(describe_change(p[0], p[1])))
    parts.append(Spacer(1, 6))
    parts.append(P(f"{d['unchanged']} findings are unchanged.", SMALL))
    if d["not_comparable"]:
        parts.append(P("Not compared (not assessed in both runs): " + ", ".join(d["not_comparable"]) + ".", SMALL))
    return parts


def build(bundle, out_path, previous=None):
    result = score(bundle, brand.load()["not_licensed"])
    rows = domain_rows(result, bundle["data"])
    ov = overall(rows)
    findings = result["findings"]
    story = [header_block(result, ov), Spacer(1, 10)]

    # ---- Executive summary ----
    story.append(P("Where you stand", H2))
    unassessed = [d for d, s in rows if s is None]
    summary = (f"{len(findings)} findings across {sum(s is not None for _, s in rows)} assessed areas: "
               f"{result['counts']['critical']} critical, {result['counts']['high']} high, "
               f"{result['counts']['medium']} medium, {result['counts']['low']} low.")
    if unassessed:
        summary += f" Not assessed (data collection failed): {', '.join(unassessed)}."
    story.append(P(summary))
    story.append(Spacer(1, 6))

    left = [scorecard(rows)]
    right = [severity_counts(result), Spacer(1, 10), P("RSC's own resilience scores", H3)]
    rt = rsc_scores_table(result)
    if rt:
        right.append(rt)
    else:
        right.append(P("Not available on this tenant.", SMALL))
    two = Table([[left, right]], colWidths=[4.4 * inch, 2.6 * inch])
    two.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                             ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(two)

    story.append(P("Priority findings", H2))
    top = [f for f in findings if f["severity"] in ("critical", "high")][:3] or findings[:3]
    for f in top:
        story.append(finding_card(f, compact=True))

    story.append(P("What to do first", H2))
    story.append(P("Each item below is a finding ID. Steps and documentation links for every finding are in "
                   "the technical appendix.", SMALL))
    story.append(Spacer(1, 3))
    for b in ("visibility", "fix_now", "process", "enterprise", "unconfirmed"):
        items = [f for f in findings if f["bucket"] == b and f["severity"] != "info"]
        if not items:
            continue
        story.append(KeepTogether([
            P(f"{BUCKET_LABEL[b]}  ({len(items)})  -  {BUCKET_NOTE[b]}", H3),
            P(", ".join(f["id"] for f in items) + ".  Titles and steps are on the roadmap and in the appendix.", CELL),
            Spacer(1, 5),
        ]))

    # ---- Roadmap and framework view ----
    story.append(PageBreak())
    story.extend(roadmap_page(findings, rows))
    if previous is not None:
        story.append(PageBreak())
        story.extend(progress_page(compute_delta(previous, bundle)))

    # ---- Appendix ----
    story.append(PageBreak())
    story.append(P("Technical appendix", H1))
    story.append(P("Every finding with its evidence and recommended action, grouped by area.", SMALL))
    by_domain = {}
    for f in findings:
        by_domain.setdefault(f["domain"], []).append(f)
    for dom in DOMAIN_SOURCES:
        if dom not in by_domain:
            continue
        # Keep the heading with its first card; keepWithNext does not reach into a KeepTogether.
        fs = by_domain[dom]
        story.append(KeepTogether([P(dom, H2)] + finding_parts(fs[0])))
        story.extend(finding_card(f) for f in fs[1:])

    story.append(PageBreak())
    story.append(P("Method and limits", H2))
    notes = [
        "Data was collected read-only through the RSC GraphQL API using a service account.",
        "Scores start at 100 per area and lose 25, 15, 7 or 3 points per critical, high, medium or low "
        "finding. This is a simple heuristic to show relative gaps, not an industry benchmark.",
        "Several thresholds (90 days stale, 24 hour MFA remember window, 2 or fewer account owners, "
        "2 or more quorum approvers, 12 character passwords) are guidance values, not Rubrik limits.",
        "Object counts are RSC object records, not distinct workloads. A VM can appear once per cluster; "
        "VM figures are collapsed to one record per VM, and templates are excluded.",
        "Test/dev detection matches names such as dev, test, qa, uat and staging. It is a heuristic and "
        "should be confirmed with the customer.",
        "RSC's own resilience scores are shown for comparison. Their object counts differ from the "
        "per-object counts here and the difference has not been reconciled.",
        "Only items in the 'Enterprise Edition' group have a confirmed entitlement. Items marked "
        "'Edition unconfirmed' have not been checked against licensing and should not be presented as "
        "upgrade benefits.",
    ]
    for n in notes:
        story.append(P("- " + n, CELL))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))
    story.append(P("Collector status", H3))
    status_rows = [[P(k, CELL), P(v if v == "ok" else v[:90], CELL)] for k, v in result["collector_status"].items()]
    st = Table(status_rows, colWidths=[1.3 * inch, 5.5 * inch])
    st.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    story.append(st)
    if result["skipped_rules"]:
        story.append(Spacer(1, 6))
        story.append(P("Rules that could not run: " + ", ".join(s["rule"] for s in result["skipped_rules"]), SMALL))

    doc = SimpleDocTemplate(str(out_path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.7 * inch, bottomMargin=0.8 * inch,
                            title=f"Cyber Readiness Assessment - {result['customer']}", author=_B["author"])
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--previous", help="earlier bundle.json from the same customer; adds a progress page")
    ap.add_argument("--style", choices=("brief", "classic"), default="brief",
                    help="brief: HTML printed by Chrome in the technical-brief style (default). "
                         "classic: reportlab, no browser needed")
    args = ap.parse_args()
    bundle_path = Path(args.bundle).expanduser()
    out = bundle_path.parent / "report.pdf"
    previous = json.loads(Path(args.previous).expanduser().read_text()) if args.previous else None
    if args.style == "brief":
        from render_html import build as build_brief
        result = build_brief(json.loads(bundle_path.read_text()), out, previous)
    else:
        print(logo_status())
        result = build(json.loads(bundle_path.read_text()), out, previous)
    print(f"wrote {out} ({len(result['findings'])} findings)")


if __name__ == "__main__":
    main()
