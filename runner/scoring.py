"""CyberHealth Score v1.0. The method is written out in SCORING.md; keep the two in step."""
from .controls import BY_ID, CONTROLS, MODULES, SCORED

VERSION = "1.0"
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
RESULT_POINTS = {"pass": 1.0, "partial": 0.5, "fail": 0.0}
MODULE_WEIGHT = {
    "discovery": 10, "tls": 15, "email": 15, "web": 10,
    "brand": 5, "services": 20, "lifecycle": 10, "vulns": 15,
}
GRADES = [(90, "A", "Strong"), (80, "B", "Good"), (70, "C", "Fair"), (60, "D", "Weak"), (0, "F", "Poor")]
CAP_KEV = 49        # a known exploited vulnerability is present
CAP_CRITICAL = 69   # any critical-severity control failed
PROVISIONAL_BELOW = 60  # coverage (%) under which the score is labelled provisional


def grade_for(score):
    for floor, letter, label in GRADES:
        if score >= floor:
            return letter, label
    return "F", "Poor"


def compute(results):
    """results: iterable of dicts with control_id and status. Returns the score breakdown."""
    by_control = {r["control_id"]: r["status"] for r in results}
    modules = {}
    total_weight = 0
    covered_weight = 0
    for control in CONTROLS:
        status = by_control.get(control.id, "not_tested")
        weight = SEVERITY_WEIGHT[control.severity]
        m = modules.setdefault(control.module, {"earned": 0.0, "possible": 0, "counts": {}})
        m["counts"][status] = m["counts"].get(status, 0) + 1
        if status == "na":
            continue
        total_weight += weight
        if status in SCORED:
            covered_weight += weight
            m["possible"] += weight
            m["earned"] += weight * RESULT_POINTS[status]

    module_scores = {}
    weighted_sum = 0.0
    weight_used = 0
    for key, label in MODULES.items():
        m = modules.get(key, {"earned": 0.0, "possible": 0, "counts": {}})
        score = round(100 * m["earned"] / m["possible"]) if m["possible"] else None
        module_scores[key] = {"label": label, "score": score, "counts": m["counts"]}
        if score is not None:
            weighted_sum += MODULE_WEIGHT[key] * (m["earned"] / m["possible"])
            weight_used += MODULE_WEIGHT[key]

    if not weight_used:
        return {"version": VERSION, "score": None, "grade": None, "label": "Not scored",
                "coverage": 0, "provisional": True, "caps": [], "modules": module_scores}

    raw = round(100 * weighted_sum / weight_used)
    caps = []
    kev = by_control.get("VUL-03") == "fail"
    critical_fail = [cid for cid, st in by_control.items()
                     if st == "fail" and cid in BY_ID and BY_ID[cid].severity == "critical"]
    score = raw
    if kev:
        caps.append(f"Known exploited vulnerability present: score capped at {CAP_KEV}.")
        score = min(score, CAP_KEV)
    if critical_fail:
        caps.append(f"Critical control failed ({', '.join(sorted(critical_fail))}): score capped at {CAP_CRITICAL}.")
        score = min(score, CAP_CRITICAL)
    coverage = round(100 * covered_weight / total_weight) if total_weight else 0
    letter, label = grade_for(score)
    return {
        "version": VERSION,
        "score": score,
        "raw_score": raw,
        "grade": letter,
        "label": label,
        "coverage": coverage,
        "provisional": coverage < PROVISIONAL_BELOW,
        "caps": caps,
        "modules": module_scores,
    }
