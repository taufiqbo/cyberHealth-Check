"""What each plan includes, set by the admin on the Plan settings page.
Stored in the settings table; the rest of the system starts applying these in a later step."""
import json

from . import audit
from .controls import MODULES

REPORTS = {"short": "Short report (executive summary) + slides", "full": "Full report (all findings) + slides"}
FREQUENCIES = {"off": "Off", "weekly": "Every week", "monthly": "Every month", "quarterly": "Every 3 months",
               "half-yearly": "Every 6 months", "yearly": "Every year"}
LIGHT_MODULES = ["discovery", "tls", "email", "web", "brand", "lifecycle"]

DEFAULTS = {
    "complimentary": {"label": "Complimentary Assessment", "report": "short", "max_domains": 1,
                      "modules": LIGHT_MODULES, "reassess": "weekly", "active": True},
    "comprehensive": {"label": "Comprehensive Assessment", "report": "full", "max_domains": 5,
                      "modules": list(MODULES), "reassess": "weekly", "active": True},
}


def get(db, key):
    row = db.one("SELECT value FROM settings WHERE key = ?", (f"plan:{key}",))
    stored = json.loads(row["value"]) if row and row["value"] else {}
    return {**DEFAULTS[key], **stored}


def all_plans(db):
    return {key: get(db, key) for key in DEFAULTS}


def default_plan(db):
    row = db.one("SELECT value FROM settings WHERE key = 'default_plan'")
    return row["value"] if row and row["value"] in DEFAULTS else "complimentary"


def _store(db, key, value):
    db.run("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
           (key, value))


def save(db, actor, key, form):
    """form: a request.form-like object. Raises ValueError with a message for the admin."""
    if key not in DEFAULTS:
        raise ValueError("Unknown plan.")
    label = (form.get("label") or "").strip()[:60]
    if not label:
        raise ValueError("Enter the plan name clients will see.")
    report = form.get("report")
    if report not in REPORTS:
        raise ValueError("Choose a report type.")
    try:
        max_domains = int(form.get("max_domains", ""))
    except ValueError:
        raise ValueError("Max domains must be a whole number.") from None
    if not 1 <= max_domains <= 500:
        raise ValueError("Max domains must be between 1 and 500.")
    modules = [m for m in MODULES if m in form.getlist("modules")]
    if not modules:
        raise ValueError("Choose at least one check area.")
    reassess = form.get("reassess")
    if reassess not in FREQUENCIES:
        raise ValueError("Choose how often domains are re-assessed.")
    active = bool(form.get("active"))
    if not active and all(not p["active"] for k, p in all_plans(db).items() if k != key):
        raise ValueError("At least one plan must stay active.")
    plan = {"label": label, "report": report, "max_domains": max_domains, "modules": modules,
            "reassess": reassess, "active": active}
    _store(db, f"plan:{key}", json.dumps(plan))
    if not active and default_plan(db) == key:
        _store(db, "default_plan", next(k for k, p in all_plans(db).items() if p["active"]))
    if form.get("make_default") and active:
        _store(db, "default_plan", key)
    audit.record(db, "plan.updated", actor, None, plan=key, **plan, default=default_plan(db) == key)
    return plan
