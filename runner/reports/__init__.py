"""Client reports: one data model, rendered as a PDF (reportlab) and a plain-language deck (python-pptx).
Two tiers: complimentary (short) and comprehensive (full)."""
from datetime import datetime

from .. import branding, scoring
from ..controls import BY_ID, MODULES
from ..db import loads
from .plain import AREA_METHODS, AREA_NAMES, AREA_PLAIN, PLAIN

TIERS = {"complimentary": "Complimentary Assessment", "comprehensive": "Comprehensive Assessment"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PRIORITY = {"critical": "Immediate", "high": "High", "medium": "Medium", "low": "Low"}
LABELS = {"A": "Excellent", "B": "Good", "C": "Moderate", "D": "Needs Improvement", "F": "Critical / Poor"}


def interpretation(score):
    if score.get("score") is None:
        return "Not enough of the model was assessed to give a score."
    grade = score["grade"]
    text = {
        "A": "The assessment shows a strong external security posture with only minor improvements suggested.",
        "B": "The assessment shows a good external security posture with a small number of improvements to make.",
        "C": "The assessment shows a moderate posture: foundations are in place, but several gaps need planned remediation.",
        "D": "The assessment indicates several areas requiring security improvement and prioritised remediation.",
        "F": "The assessment indicates serious weaknesses that need urgent attention.",
    }[grade]
    if score.get("caps"):
        text += " The score was capped because of a critical finding."
    return text


def _date(value):
    if not value:
        return ""
    d = datetime.fromisoformat(value)
    return f"{d.day} {d.strftime('%B %Y')}"  # no %-d: it does not exist on Windows


def build(service, assessment_id, tier):
    """Everything a report needs, already in client language."""
    a = service.assessment(assessment_id)
    client = service.db.one("SELECT * FROM clients WHERE id = ?", (a["client_id"],))
    results = service.results(assessment_id)
    score = loads(a["score_json"]) if a["signed_off_at"] else service.score(assessment_id)
    disc = service.prior_evidence(assessment_id).get("discovery", {})
    assets = [h["name"] for h in disc.get("hosts", []) if h.get("resolves")]

    findings, positives, review_items = [], [], []
    for r in results:
        c = BY_ID[r["control_id"]]
        p = PLAIN[c.id]
        row = {"control": c.id, "area": AREA_NAMES[c.module], "module": c.module, "severity": c.severity,
               "title": p["finding"], "technical_title": c.title, "evidence": r["summary"],
               "impact": p["impact"], "action": p["action"], "technical_impact": c.why, "fix": c.fix,
               "priority": PRIORITY[c.severity], "review_note": r["review_note"], "status": r["status"],
               "state": "Partial" if r["status"] == "partial" else "Confirmed"}
        if r["status"] in ("fail", "partial"):
            findings.append(row)
        elif r["status"] == "pass":
            positives.append({**row, "good": p["good"]})
        elif r["status"] in ("review", "inconclusive"):
            review_items.append(row)
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], 0 if f["status"] == "fail" else 1, f["control"]))
    positives.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["control"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"

    areas = []
    total_weight = sum(scoring.MODULE_WEIGHT.values())
    for key in MODULES:
        m = score["modules"].get(key, {})
        s = m.get("score")
        weight = round(100 * scoring.MODULE_WEIGHT[key] / total_weight)
        areas.append({"key": key, "name": AREA_NAMES[key], "plain": AREA_PLAIN[key], "method": AREA_METHODS[key],
                      "score": s, "weight": weight, "grade": scoring.grade_for(s)[0] if s is not None else None,
                      "contribution": round(s * weight / 100, 2) if s is not None else None,
                      "band": LABELS[scoring.grade_for(s)[0]] if s is not None else "Not assessed"})
    not_assessed = [x for x in areas if x["score"] is None]

    sev_counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    grade = score.get("grade")
    auto_summary = (
        f"This {TIERS[tier].lower()} reviewed the publicly observable security posture of {a['target']}. "
        f"It found {len(findings)} item(s) to improve and {len(positives)} control(s) working as expected. "
        + (f"The overall result is {score['score']}/100, grade {grade} ({LABELS[grade]})."
           if score.get("score") is not None else "There was not enough data to give an overall score.")
        + (" Some areas were not assessed in this cycle: " + ", ".join(x["name"] for x in not_assessed) + "."
           if not_assessed else ""))
    signer = service.user(a["signed_off_by"]) if a["signed_off_by"] else None
    brand = branding.for_client(service.db, service.config, client)
    logo = branding.logo_path(service.config, brand["logo"])
    return {
        "tier": tier, "tier_label": TIERS[tier],
        "brand": brand["name"], "legal": brand["name"] if brand.get("custom") else service.config.brand_legal,
        "logo_path": str(logo) if logo else None,
        "client": client["name"], "target": a["target"],
        "date": _date(a["signed_off_at"] or a["created_at"]), "draft": not a["signed_off_at"],
        "created": _date(a["created_at"]), "signer": signer["name"] if signer else ("Automatic (no change)" if a.get("auto_from") else ""),
        "score": score, "label": LABELS.get(grade, "Not scored"), "interpretation": interpretation(score),
        "summary": (a.get("summary_text") or "").strip() or auto_summary,
        "findings": findings, "positives": positives, "review_items": review_items,
        "areas": areas, "not_assessed": not_assessed, "assets": assets, "sev_counts": sev_counts,
        "results": results,
    }


def filename(data, ext):
    safe = "".join(ch if ch.isalnum() or ch in "-." else "-" for ch in data["target"])
    kind = "Comprehensive" if data["tier"] == "comprehensive" else "Complimentary"
    brand = "".join(ch for ch in data["brand"].title() if ch.isalnum()) or "CyberHealth"
    return f"{brand}_{kind}_Assessment_{safe}.{ext}"
