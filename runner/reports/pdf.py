"""PDF reports in the BINTARA report style (teal tables, navy headings, scorecard on page 1)."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (Image, KeepTogether, ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from .plain import GLOSSARY

NAVY = colors.HexColor("#12263F")
NAVY_DARK = colors.HexColor("#0F1E2E")
PANEL = colors.HexColor("#132B45")
TEAL = colors.HexColor("#0E7C86")
TEXT = colors.HexColor("#27313D")
MUTED = colors.HexColor("#6B7785")
ROW = colors.HexColor("#F3F6F9")
LINE = colors.HexColor("#C9D1DA")
YELLOW = colors.HexColor("#FFF3CD")
BLUE = colors.HexColor("#DCE9F7")
ORANGE = colors.HexColor("#E07B2A")
GRADE_COLOURS = {"A": "#1F9254", "B": "#7CB342", "C": "#E0A526", "D": "#E07B2A", "F": "#D64541", None: "#9AA5B1"}
SEV_COLOURS = {"critical": "#B3261E", "high": "#D64541", "medium": "#E0A526", "low": "#6B7785"}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
WIDTH = PAGE_W - 2 * MARGIN

S = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=NAVY,
                            alignment=TA_CENTER, spaceAfter=6),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=TEAL,
                               alignment=TA_CENTER, spaceAfter=10),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17, leading=22, textColor=NAVY, spaceBefore=6,
                         spaceAfter=8),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=TEAL, spaceBefore=8,
                         spaceAfter=4),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.5, leading=13, textColor=NAVY, spaceBefore=6,
                         spaceAfter=2),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=TEXT, spaceAfter=4),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.3, leading=11, textColor=TEXT),
    "cellc": ParagraphStyle("cellc", fontName="Helvetica", fontSize=8.3, leading=11, textColor=TEXT,
                            alignment=TA_CENTER),
    "head": ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white,
                           alignment=TA_CENTER),
    "box_title": ParagraphStyle("box_title", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=NAVY,
                                spaceAfter=3),
    "toc": ParagraphStyle("toc", fontName="Helvetica", fontSize=10, leading=17, textColor=TEXT),
}


def P(text, style="body"):
    return Paragraph(escape(str(text if text is not None else "")), S[style])


def table(header, rows, widths, center_cols=(0,)):
    data = [[Paragraph(escape(h), S["head"]) for h in header]]
    for row in rows:
        data.append([Paragraph(escape(str(v if v is not None else "")), S["cellc" if i in center_cols else "cell"])
                     for i, v in enumerate(row)])
    t = Table(data, colWidths=[w * WIDTH for w in widths], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), TEAL), ("GRID", (0, 0), (-1, -1), 0.6, LINE),
             ("BOX", (0, 0), (-1, -1), 0.9, NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i in range(1, len(data)):
        if i % 2 == 1:
            style.append(("BACKGROUND", (0, i), (-1, i), ROW))
    t.setStyle(TableStyle(style))
    return t


def callout(title, text, colour):
    t = Table([[[Paragraph(escape(title), S["box_title"]), P(text)]]], colWidths=[WIDTH])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colour), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    return t


def bullets(items):
    return ListFlowable([ListItem(P(i), leftIndent=12) for i in items], bulletType="bullet", start="•",
                        leftIndent=14, bulletFontSize=8)


def numbered(items, start=1):
    return ListFlowable([ListItem(P(i), leftIndent=14) for i in items], bulletType="1", start=start, leftIndent=16,
                        bulletFontSize=9)


# Scorecard ----------------------------------------------------------------------
def _ring(d, cx, cy, r, width, pct, colour):
    track = Wedge(cx, cy, r, 0, 360, radius1=r - width)
    track.fillColor, track.strokeColor = colors.HexColor("#2A4563"), None
    d.add(track)
    if pct > 0:
        sweep = 360 * min(pct, 100) / 100
        arc = Wedge(cx, cy, r, 90 - sweep, 90, radius1=r - width)
        arc.fillColor, arc.strokeColor = colors.HexColor(colour), None
        d.add(arc)


def scorecard(data):
    score = data["score"]
    h = 200
    d = Drawing(WIDTH, h)
    d.add(Rect(0, h - 24, WIDTH, 24, fillColor=NAVY_DARK, strokeColor=None))
    d.add(String(12, h - 16, "EXECUTIVE CYBER RISK SCORECARD", fontName="Helvetica-Bold", fontSize=9,
                 fillColor=colors.white))
    d.add(String(WIDTH - 10, h - 15, f"{data['target']} · {data['date']} · {data['tier_label']}",
                 fontName="Helvetica", fontSize=6.5, fillColor=colors.HexColor("#B8C4D0"), textAnchor="end"))
    d.add(Rect(0, 0, 150, h - 24, fillColor=PANEL, strokeColor=None))
    d.add(Rect(150, 0, WIDTH - 150, h - 24, fillColor=colors.white, strokeColor=LINE, strokeWidth=0.5))
    grade = score.get("grade")
    value = score.get("score")
    _ring(d, 60, 118, 36, 7, value or 0, GRADE_COLOURS[grade] if grade else "#9AA5B1")
    d.add(String(60, 116, grade or "–", fontName="Helvetica-Bold", fontSize=24, fillColor=colors.white,
                 textAnchor="middle"))
    d.add(String(60, 102, f"{value if value is not None else '–'} / 100", fontName="Helvetica", fontSize=7,
                 fillColor=colors.HexColor("#C5D0DB"), textAnchor="middle"))
    d.add(String(12, 64, data["label"].upper(), fontName="Helvetica-Bold", fontSize=7.5,
                 fillColor=colors.HexColor(GRADE_COLOURS[grade] if grade else "#9AA5B1")))
    d.add(Rect(12, 58, 126, 0.5, fillColor=colors.HexColor("#3A5573"), strokeColor=None))
    d.add(String(12, 46, f"Coverage: {score.get('coverage', 0)}% of the model", fontName="Helvetica", fontSize=6.5,
                 fillColor=colors.HexColor("#B8C4D0")))
    if score.get("provisional"):
        d.add(String(12, 36, "Provisional (partial coverage)", fontName="Helvetica", fontSize=6.5,
                     fillColor=colors.HexColor("#B8C4D0")))
    if data["tier"] == "comprehensive":
        _category_donut(d, data, h)
    else:
        _band_and_signals(d, data, h)
    return d


def _band_and_signals(d, data, h):
    x0 = 170
    d.add(String(x0, h - 46, "WHERE THIS SCORE SITS", fontName="Helvetica-Bold", fontSize=6.5, fillColor=MUTED))
    bands = [("F", "0-59", 56), ("D", "60-69", 24), ("C", "70-79", 24), ("B", "80-89", 24), ("A", "90-100", 24)]
    x = x0
    for letter, rng, w in bands:
        active = letter == data["score"].get("grade")
        d.add(Rect(x, h - 82, w, 26, fillColor=colors.HexColor("#FDEBDD") if active else ROW,
                   strokeColor=ORANGE if active else LINE, strokeWidth=0.8 if active else 0.4))
        d.add(String(x + w / 2, h - 67, letter, fontName="Helvetica-Bold", fontSize=8,
                     fillColor=ORANGE if active else MUTED, textAnchor="middle"))
        d.add(String(x + w / 2, h - 77, rng, fontName="Helvetica", fontSize=5, fillColor=MUTED, textAnchor="middle"))
        x += w
    text = data["interpretation"]
    for i, line in enumerate(_wrap(text, 48)[:5]):
        d.add(String(x0, h - 100 - i * 10, line, fontName="Helvetica", fontSize=6.8, fillColor=TEXT))
    sx = WIDTH - 122
    d.add(String(sx, h - 46, "KEY SIGNALS", fontName="Helvetica-Bold", fontSize=6.5, fillColor=MUTED))
    counts = data["sev_counts"]
    signals = [(len(data["findings"]), "Risk-based findings", ORANGE),
               (counts["critical"] + counts["high"], "Critical / high signals", colors.HexColor("#D64541")),
               (len(data["positives"]), "Positive signals", colors.HexColor("#1F9254")),
               (f"{data['score'].get('coverage', 0)}%", "Model coverage assessed", colors.HexColor("#9AA5B1"))]
    for i, (n, label, colour) in enumerate(signals):
        y = h - 66 - i * 28
        d.add(Circle(sx + 9, y, 9, fillColor=colour, strokeColor=None))
        d.add(String(sx + 9, y - 2.5, str(n), fontName="Helvetica-Bold", fontSize=6.5 if len(str(n)) > 2 else 7.5,
                     fillColor=colors.white, textAnchor="middle"))
        d.add(String(sx + 24, y - 2.5, label, fontName="Helvetica-Bold", fontSize=6.5, fillColor=TEXT))


def _category_donut(d, data, h):
    cx, cy, r = 250, 88, 62
    total = sum(a["weight"] for a in data["areas"])
    start = 90
    for a in data["areas"]:
        sweep = 360 * a["weight"] / total
        w = Wedge(cx, cy, r, start - sweep, start, radius1=r - 20)
        w.fillColor, w.strokeColor, w.strokeWidth = colors.HexColor(GRADE_COLOURS[a["grade"]]), colors.white, 1.5
        d.add(w)
        start -= sweep
    d.add(String(cx, cy + 1, str(data["score"].get("score") if data["score"].get("score") is not None else "–"),
                 fontName="Helvetica-Bold", fontSize=15, fillColor=NAVY, textAnchor="middle"))
    d.add(String(cx, cy - 10, f"{len(data['areas'])} CATEGORIES", fontName="Helvetica", fontSize=5,
                 fillColor=MUTED, textAnchor="middle"))
    d.add(String(cx, h - 40, "SCORE BY CATEGORY — SIZE = WEIGHT", fontName="Helvetica-Bold", fontSize=5.5,
                 fillColor=MUTED, textAnchor="middle"))
    lx = 345
    for i, a in enumerate(data["areas"]):
        y = h - 42 - i * 19
        d.add(Circle(lx + 6, y, 6, fillColor=colors.HexColor(GRADE_COLOURS[a["grade"]]), strokeColor=None))
        d.add(String(lx + 6, y - 2, a["grade"] or "–", fontName="Helvetica-Bold", fontSize=5.5,
                     fillColor=colors.white, textAnchor="middle"))
        d.add(String(lx + 16, y + 1, a["name"], fontName="Helvetica-Bold", fontSize=6, fillColor=TEXT))
        sub = f"{a['score']}/100 · {a['weight']}% weight" if a["score"] is not None else "Not assessed this cycle"
        d.add(String(lx + 16, y - 6.5, sub, fontName="Helvetica", fontSize=5, fillColor=MUTED))


def _wrap(text, width):
    words, lines, line = text.split(), [], ""
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


# Page furniture -------------------------------------------------------------------
def _canvas_class(data):
    header = f"CONFIDENTIAL - CUSTOMER SECURITY ASSESSMENT  |  {data['tier_label'].upper()}"
    if data["draft"]:
        header = "DRAFT - NOT REVIEWED  |  " + header
    footer = f"{data['legal']}  |  {data['date']}"

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self.setFont("Helvetica-Bold", 7.5)
                self.setFillColor(TEAL)
                self.drawCentredString(PAGE_W / 2, PAGE_H - 11 * mm, header)
                self.setFont("Helvetica", 7.5)
                self.setFillColor(MUTED)
                self.drawCentredString(PAGE_W / 2, 10 * mm, f"{footer}  |  Page {self._pageNumber} of {total}")
                super().showPage()
            super().save()
    return NumberedCanvas


def _logo(path, max_w=55 * mm, max_h=18 * mm):
    img = Image(path)
    ratio = min(max_w / img.imageWidth, max_h / img.imageHeight)
    img.drawWidth, img.drawHeight = img.imageWidth * ratio, img.imageHeight * ratio
    img.hAlign = "LEFT"
    return img


def _cover(data, subtitle):
    kind = "COMPREHENSIVE" if data["tier"] == "comprehensive" else "COMPLIMENTARY"
    story = [Spacer(1, 4)]
    if data.get("logo_path"):
        story += [_logo(data["logo_path"]), Spacer(1, 6)]
    story += [P(f"{data['brand']} - {kind} SECURITY & DIGITAL ASSESSMENT REPORT",
                              "title"), P(subtitle, "subtitle")]
    story.append(table(["Assessment field", "Value"], [
        ("Organisation", data["client"]), ("Domain assessed", data["target"]),
        ("Assessment date", data["date"]), ("Assessment type", data["tier_label"]),
        ("Assessed coverage", f"{data['score'].get('coverage', 0)}% of the CyberHealth model"),
    ], [0.5, 0.5]))
    story += [Spacer(1, 12), scorecard(data), Spacer(1, 10),
              callout("ASSESSMENT INTERPRETATION", data["interpretation"], YELLOW)]
    return story


# Complimentary ----------------------------------------------------------------------
def complimentary(data):
    story = _cover(data, "Executive Customer Assessment")
    story.append(PageBreak())
    story += [P("1. Executive Summary", "h1"), P(data["summary"]), P("Overall condition", "h2"),
              P(f"The current posture is best described as {data['label']}. " + data["interpretation"]),
              P("Key observations", "h2")]
    obs = [f"{f['title']} ({f['severity']}): {f['evidence']}" for f in data["findings"][:5]]
    story.append(bullets(obs or ["No significant weaknesses were observed in the assessed areas."]))
    story += [Spacer(1, 6), callout("Business meaning", "These observations do not prove that a compromise has occurred. "
                                    "They show where exposure is larger than necessary or a defensive layer is missing, "
                                    "which could increase the impact if another weakness or misuse occurs.", BLUE)]
    story += [P("2. Key Findings", "h1")]
    rows = [(i, f["title"], f["severity"].title(), f["impact"], f["state"]) for i, f in enumerate(data["findings"][:7], 1)]
    story.append(table(["#", "Finding", "Severity", "Business impact", "Status"], rows or [("–", "None", "", "", "")],
                       [0.07, 0.3, 0.13, 0.35, 0.15], center_cols=(0, 2)))
    story += [P("3. Positive Findings", "h1"),
              bullets([p["good"] for p in data["positives"][:8]] or ["No controls passed in the assessed areas."])]
    story += [P("4. Priority Recommendations", "h1")]
    rows = [(f["action"], f["priority"], f["impact"], f["fix"]) for f in data["findings"][:6]]
    story.append(table(["Recommendation", "Priority", "Why it matters", "Suggested next step"],
                       rows or [("No urgent actions", "", "", "")], [0.28, 0.12, 0.3, 0.3], center_cols=(1,)))
    story += [P("5. Complimentary Assessment Limitations", "h1"),
              P("This service was a limited, point-in-time External CyberHealth Check. It did not include full-depth "
                "infrastructure testing, internal network testing, authenticated application testing, source-code "
                "review, credential testing, manual exploitation, full compliance assessment, or continuous monitoring.")]
    if data["not_assessed"]:
        story.append(callout("Areas not assessed this cycle",
                             ", ".join(a["name"] for a in data["not_assessed"]) + ". Not assessed does not mean "
                             "free of issues; these areas need provider approval or further work.", YELLOW))
    story += [P("A comprehensive assessment adds the complete findings register, detailed technical findings, risk "
                "prioritisation, a remediation roadmap and approved vulnerability scanning where permission exists.")]
    story += [P("6. Recommended Next Steps", "h1")]
    now = [f["action"] for f in data["findings"] if f["severity"] in ("critical", "high")][:4]
    soon = [f["action"] for f in data["findings"] if f["severity"] in ("medium", "low")][:4]
    if now:
        story += [P("Immediate actions", "h2"), numbered(now)]
    if soon:
        story += [P("Short-term actions", "h2"), numbered(soon, start=len(now) + 1)]
    story += [Spacer(1, 6), callout("Next assessment statement",
                                    "This complimentary assessment gives a high-level view of the current posture. "
                                    "A comprehensive assessment provides deeper technical validation, risk "
                                    "prioritisation and remediation guidance.", BLUE)]
    return story


# Comprehensive ---------------------------------------------------------------------
SECTIONS = ["Management Executive Summary", "Assessment Scope and Methodology", "Overall Security Score",
            "Complete Findings Register", "Detailed Findings", "Risk Prioritisation", "Remediation Roadmap",
            "Security Strengths", "Areas for Improvement", "Business Risk Summary", "Detailed Recommendations",
            "Assessment Limitations", "Conclusion"]


def comprehensive(data):
    story = _cover(data, "Detailed Technical & Executive Assessment")
    story += [PageBreak(), P("Table of Contents", "h1")]
    for i, name in enumerate(SECTIONS, 1):
        story.append(P(f"{i}. {name}", "toc"))
    for name in ("Appendix A. Technical Observations", "Appendix B. Reviewer Clarifications", "Appendix C. Glossary"):
        story.append(P(name, "toc"))
    story += [Spacer(1, 8), callout("Report classification", "This report is an External CyberHealth Check. It is not "
                                    "a full penetration test. Findings are limited to observed or correlated evidence "
                                    "collected within the stated scope.", BLUE), PageBreak()]
    f, s = data["findings"], data["score"]
    # 1
    story += [P("1. Management Executive Summary", "h1"), P(data["summary"]), P("Overall security posture", "h2"),
              P(data["interpretation"]), P("Main strengths", "h2"),
              bullets([p["good"] for p in data["positives"][:6]] or ["None recorded."]),
              P("Main weaknesses", "h2"), bullets([x["title"] for x in f[:6]] or ["None recorded."]),
              P("Highest-priority remediation areas", "h2"), numbered([x["action"] for x in f[:6]] or ["None."])]
    # 2
    story += [PageBreak(), P("2. Assessment Scope and Methodology", "h1"), P("2.1 Target and objectives", "h2"),
              P(f"Primary domain: {data['target']}. The assessment aimed to identify externally observable asset, "
                "transport, email, web, service, lifecycle, vulnerability and brand-protection risks without "
                "exploitation or service disruption."),
              P("2.2 Assessment date", "h2"),
              P(f"The assessment started on {data['created']}. The report date is {data['date']}."),
              P("2.3 Areas reviewed", "h2"),
              table(["Area", "Method actually used"],
                    [(a["name"], a["method"] if a["score"] is not None else "Not assessed this cycle.")
                     for a in data["areas"]], [0.35, 0.65])]
    if data["assets"]:
        story += [P("2.4 Discovered internet-facing host names", "h2"),
                  table(["#", "Host name"], [(i, h) for i, h in enumerate(data["assets"][:60], 1)], [0.12, 0.88])]
    story += [P("2.5 Evidence and restrictions", "h2"),
              P("Evidence includes DNS responses, HTTP headers, TLS handshakes, scan output and imported reports, each "
                "stored with a SHA-256 integrity hash. No exploitation, login, credential, database, file retrieval, "
                "internal network or denial-of-service testing was performed.")]
    # 3
    rows = [(a["name"], a["score"] if a["score"] is not None else "Not assessed", f"{a['weight']}%",
             a["contribution"] if a["contribution"] is not None else "-", a["band"]) for a in data["areas"]]
    story += [PageBreak(), P("3. Overall Security Score", "h1"),
              table(["Category", "Score /100", "Weight", "Contribution", "Interpretation"], rows,
                    [0.32, 0.14, 0.12, 0.16, 0.26], center_cols=(1, 2, 3)), Spacer(1, 8),
              callout("Scoring method", f"Each control is weighted by severity (critical 10, high 6, medium 3, low 1); "
                      "Pass earns full points, Partial half, Fail none. Categories are combined with the weights above. "
                      "Categories not assessed are left out rather than counted as zero, and the result is shown with "
                      f"its coverage ({s.get('coverage', 0)}%). " + " ".join(s.get("caps", [])), BLUE),
              P("Grade translation", "h2"),
              table(["Score", "Grade", "Assessment level"], [("90-100", "A", "Excellent"), ("80-89", "B", "Good"),
                    ("70-79", "C", "Moderate"), ("60-69", "D", "Needs Improvement"), ("0-59", "F", "Critical / Poor")],
                    [0.33, 0.33, 0.34], center_cols=(0, 1))]
    # 4
    story += [PageBreak(), P("4. Complete Findings Register", "h1")]
    rows = [(x["id"], x["title"], x["severity"].title(), x["state"], x["evidence"], x["impact"], x["action"]) for x in f]
    story.append(table(["ID", "Finding", "Severity", "Status", "Evidence summary", "Business risk", "Recommendation"],
                       rows or [("-", "No findings", "", "", "", "", "")],
                       [0.08, 0.16, 0.1, 0.1, 0.2, 0.18, 0.18], center_cols=(0, 2)))
    c = data["sev_counts"]
    story += [Spacer(1, 6), callout("Finding statistics", f"{len(f)} findings: {c['critical']} Critical, {c['high']} High, "
                                    f"{c['medium']} Medium and {c['low']} Low. Positive observations and areas not "
                                    "assessed are excluded.", YELLOW)]
    # 5
    story += [PageBreak(), P("5. Detailed Findings", "h1")]
    for x in f:
        block = [P(f"{x['id']} - {x['title']}", "h2"),
                 table(["Field", "Assessment"], [("Control", f"{x['control']} · {x['technical_title']}"),
                       ("Area", x["area"]), ("Severity", x["severity"].title()), ("Status", x["state"]),
                       ("Priority", x["priority"])], [0.4, 0.6]),
                 P("Description and evidence", "h3"), P(x["evidence"]), P("Technical impact", "h3"),
                 P(x["technical_impact"]), P("Business impact", "h3"), P(x["impact"]), P("Recommendation", "h3"),
                 P(x["fix"])]
        if x["review_note"]:
            block += [P("Reviewer note", "h3"), P(x["review_note"])]
        story.append(KeepTogether(block[:3]))
        story += block[3:]
    if not f:
        story.append(P("No findings were recorded."))
    # 6, 7
    story += [PageBreak(), P("6. Risk Prioritisation", "h1"),
              table(["ID", "Finding", "Severity", "Priority"], [(x["id"], x["title"], x["severity"].title(),
                    x["priority"]) for x in f] or [("-", "None", "", "")], [0.12, 0.52, 0.18, 0.18], center_cols=(0, 2, 3)),
              P("7. Remediation Roadmap", "h1")]
    phases = [("Now (0-7 days)", [x for x in f if x["severity"] == "critical"]),
              ("Next 30 days", [x for x in f if x["severity"] == "high"]),
              ("Next 90 days", [x for x in f if x["severity"] in ("medium", "low")])]
    for name, items in phases:
        story += [P(name, "h2"), bullets([f"{x['id']}: {x['action']}" for x in items] or ["Nothing in this phase."])]
    if data["not_assessed"]:
        story += [P("To complete coverage", "h2"),
                  bullets([f"Assess {a['name']}." for a in data["not_assessed"]])]
    # 8, 9, 10, 11
    partial = [x for x in f if x["status"] == "partial"]
    story += [P("8. Security Strengths", "h1"), bullets([p["good"] for p in data["positives"]] or ["None recorded."]),
              P("9. Areas for Improvement", "h1"),
              bullets([f"{x['title']}: {x['evidence']}" for x in partial] or ["No partially met controls."]),
              PageBreak(), P("10. Business Risk Summary", "h1")]
    rows = []
    for a in data["areas"]:
        items = [x for x in f if x["area"] == a["name"]]
        rows.append((a["name"], a["band"], "; ".join(x["impact"] for x in items[:2]) or
                     ("Not assessed this cycle." if a["score"] is None else "No significant business risk observed.")))
    story += [table(["Area", "Level", "What it means for the business"], rows, [0.27, 0.18, 0.55]),
              P("11. Detailed Recommendations", "h1"),
              table(["ID", "Recommendation", "Priority"], [(x["id"], x["fix"], x["priority"]) for x in f]
                    or [("-", "None", "")], [0.12, 0.7, 0.18], center_cols=(0, 2))]
    # 12, 13
    story += [P("12. Assessment Limitations", "h1"),
              P("This is a point-in-time, outside-in assessment. It does not include internal testing, authenticated "
                "application testing, source-code review, credential testing or exploitation.")]
    if data["not_assessed"]:
        story.append(callout("Not assessed this cycle", ", ".join(a["name"] for a in data["not_assessed"]) +
                             ". These categories are excluded from the score, not treated as zero or as passed.", YELLOW))
    story += [P("13. Conclusion", "h1"), P(data["interpretation"] + " Addressing the immediate and 30-day items in the "
                                           "roadmap will give the largest improvement in the shortest time.")]
    # Appendices
    story += [PageBreak(), P("Appendix A. Technical Observations", "h1"),
              table(["Control", "Result", "Observation"], [(r["control_id"], r["status"].replace("_", " ").title(),
                    r["summary"]) for r in data["results"]], [0.13, 0.15, 0.72], center_cols=(0, 1)),
              P("Appendix B. Reviewer Clarifications", "h1")]
    notes = [(r["control_id"], r["review_note"]) for r in data["results"] if r["review_note"]]
    story.append(table(["Control", "Clarification"], notes, [0.15, 0.85]) if notes else P("No clarifications recorded."))
    story += [P("Appendix C. Glossary", "h1"), table(["Term", "Meaning"], GLOSSARY, [0.25, 0.75])]
    return story


def render(data):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"{data['tier_label']} - {data['target']}",
                            author=data["legal"])
    story = comprehensive(data) if data["tier"] == "comprehensive" else complimentary(data)
    doc.build(story, canvasmaker=_canvas_class(data))
    return buf.getvalue()
