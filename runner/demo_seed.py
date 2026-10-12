"""Demo data: a fictional client with one signed-off assessment and one waiting for review."""
import shutil
from pathlib import Path

from . import accounts
from .demo_net import DEMO_DIR, DOMAIN

PEOPLE = [
    ("admin@demo.example", "Ada Admin", "demo-admin", ["admin"]),
    ("analyst@demo.example", "Arif Analyst", "demo-analyst", ["analyst"]),
    ("reviewer@demo.example", "Rina Reviewer", "demo-reviewer", ["reviewer"]),
]
DECISIONS = {
    "WEB-02": ("pass", "Demo: opened the home page; it shows the normal company site."),
    "BRD-01": ("pass", "Demo: both live lookalikes show parking pages, not copies of the site."),
    "TLS-06": ("pass", "Demo: confirmed with nmap ssl-enum-ciphers; no RC4 or 3DES offered."),
    "SVC-04": ("fail", "Demo: port 8443 shows a router admin login page open to the internet."),
}


def seed(service):
    db = service.db
    client_id = db.run("INSERT INTO clients (name, contact_email, created_at) VALUES (?, ?, datetime('now'))",
                       ("Client Example Ltd (fictional)", f"client@{DOMAIN}"))
    ids = {}
    for email, name, password, roles in PEOPLE:
        ids[roles[0]] = accounts.create_user(db, email, name, password, roles, check_strength=False)
    ids["client"] = accounts.create_user(db, f"client@{DOMAIN}", "Chen Client", "demo-client", ["client"],
                                         client_id=client_id, check_strength=False)
    analyst = service.user(ids["analyst"])
    reviewer = service.user(ids["reviewer"])

    # 1. A full assessment, reviewed and signed off.
    first = service.create_assessment(analyst, client_id, DOMAIN)
    service.check_ownership(first, analyst)
    service.work_until_idle()
    scope = service.prior_evidence(first)["discovery"]["scan_scope"]
    service.confirm_headsup(first, analyst, "Demo: emailed the hosting provider's abuse desk with the scan IP.", scope)
    service.record_approval(first, analyst, "Demo: written approval from the hosting provider, ref HP-0001.")
    upload = Path(service.config.uploads_dir) / str(first)
    upload.mkdir(parents=True, exist_ok=True)
    report = upload / "greenbone-sample.xml"
    shutil.copy(DEMO_DIR / "greenbone-sample.xml", report)
    service.record_report(first, analyst, str(report))
    service.work_until_idle()
    for row in service.results(first):
        if not row["needs_review"] or row["reviewed_at"]:
            continue
        status, note = DECISIONS.get(row["control_id"], (row["status"], "Demo: checked and confirmed."))
        if status in ("review", "inconclusive"):
            status = "pass"
        service.review_result(first, row["control_id"], reviewer, status, note)
    service.sign_off(first, reviewer, "Demo sign-off.")

    # 2. A newer assessment, automatic modules done, waiting for the reviewer.
    second = service.create_assessment(analyst, client_id, DOMAIN)
    service.check_ownership(second, analyst)
    service.work_until_idle()
    return first, second
