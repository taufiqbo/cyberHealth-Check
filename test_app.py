"""Tests for CyberHealth Runner. Run: python3 -m pytest -q test_app.py"""
import json
import re
from pathlib import Path

import pytest

from app import create_app
from runner import accounts, audit, eol, ownership, scoring
from runner.checks import Context
from runner.checks import email as email_check
from runner.checks import tls as tls_check
from runner.checks.services import parse_nmap
from runner.checks.vulns import parse_greenbone
from runner.config import load_config
from runner.controls import CONTROLS
from runner.demo_net import DEMO_DIR, DOMAIN, DemoNet
from runner.pipeline import GateClosed

ADMIN = ("boss@runner.example", "a-long-password")


# Helpers ---------------------------------------------------------------------
def make_app(tmp_path, demo=False):
    cfg = load_config(demo=demo, data_dir=Path(tmp_path), admin_email=ADMIN[0], admin_password=ADMIN[1],
                      secure_cookies=False, inline_worker=False)
    if demo:
        return create_app(cfg, start_worker=False)
    holder = {}
    net = DemoNet(token_lookup=lambda d: [r["ownership_token"] for r in holder["db"].all(
        "SELECT ownership_token FROM assessments WHERE target = ?", (d,))])
    app = create_app(cfg, net=net, start_worker=False)
    holder["db"] = app.extensions["runner"].db
    return app


def csrf_of(client):
    page = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def login(client, email, password):
    token = csrf_of(client)
    return client.post("/login", data={"email": email, "password": password, "csrf": token})


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


@pytest.fixture
def demo(tmp_path):
    return make_app(tmp_path, demo=True)


@pytest.fixture
def live(tmp_path):
    """Non-demo app (bootstrap admin, no seed) answered by the demo fixtures."""
    return make_app(tmp_path)


def add_people(service, *specs):
    admin = service.db.one("SELECT * FROM users WHERE email = ?", (ADMIN[0],))
    cid = service.db.run("INSERT INTO clients (name, contact_email, created_at) VALUES ('Acme', 'it@acme.example', 'x')")
    ids = {}
    for email, roles in specs:
        ids[email] = accounts.create_user(service.db, email, email, "a-long-password", roles,
                                          client_id=cid if "client" in roles else None, actor=admin)
    return cid, ids


# Scoring ---------------------------------------------------------------------
def test_score_all_pass_is_100_A():
    s = scoring.compute([{"control_id": c.id, "status": "pass"} for c in CONTROLS])
    assert (s["score"], s["grade"], s["coverage"], s["provisional"]) == (100, "A", 100, False)


def test_score_caps_for_kev_and_critical():
    rows = [{"control_id": c.id, "status": "pass"} for c in CONTROLS]
    by = {r["control_id"]: r for r in rows}
    by["SVC-02"]["status"] = "fail"
    s = scoring.compute(rows)
    assert s["score"] <= scoring.CAP_CRITICAL and s["raw_score"] > s["score"]
    by["VUL-03"]["status"] = "fail"
    assert scoring.compute(rows)["score"] <= scoring.CAP_KEV


def test_score_excludes_untested_and_na():
    rows = [{"control_id": "TLS-01", "status": "pass"}, {"control_id": "TLS-02", "status": "na"}]
    s = scoring.compute(rows)
    assert s["score"] == 100 and s["provisional"] and s["coverage"] < 10
    assert scoring.compute([])["score"] is None


def test_partial_is_half():
    rows = [{"control_id": c.id, "status": "partial" if c.module == "email" else "na"} for c in CONTROLS]
    assert scoring.compute(rows)["score"] == 50


# Targets and ownership -------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("https://www.Example.com/path", ("example.com", "domain")),
    ("shop.example.co.uk", ("shop.example.co.uk", "domain")),
    ("8.8.8.8", ("8.8.8.8", "ip")),
])
def test_normalise_target_ok(raw, expected):
    assert ownership.normalise_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "10.0.0.1", "127.0.0.1", "localhost", "-oX.com", "exa mple.com", "a_b.com"])
def test_normalise_target_rejects(raw):
    with pytest.raises(ValueError):
        ownership.normalise_target(raw)


def test_ownership_needs_the_exact_token():
    a = {"target": DOMAIN, "target_type": "domain", "ownership_token": "chk-right"}
    net = DemoNet(token_lookup=lambda d: ["chk-wrong"])
    assert ownership.check(net, a)[0] is False
    net = DemoNet(token_lookup=lambda d: ["chk-right"])
    assert ownership.check(net, a)[:2] == (True, "dns")


def test_nothing_runs_before_ownership(live):
    service = live.extensions["runner"]
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, "unknown-domain.example")
    assert service.check_ownership(aid)[0] is False
    for module in ("discovery", "tls", "email", "web", "brand", "services", "vulns"):
        with pytest.raises(GateClosed):
            service.enqueue(aid, module, analyst)
    assert service.db.all("SELECT * FROM module_runs") == []


def test_manual_ownership_needs_a_note(live):
    service = live.extensions["runner"]
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, "unknown-domain.example")
    with pytest.raises(ValueError):
        service.record_manual_ownership(aid, analyst, "   ")
    service.record_manual_ownership(aid, analyst, "Signed letter from IT manager, 1 Oct")
    queued = {r["module"] for r in service.db.all("SELECT module FROM module_runs")}
    assert queued == {"discovery", "tls", "email", "web", "brand", "lifecycle"}


def test_unresolvable_domain_is_inconclusive_not_failed(live):
    service = live.extensions["runner"]
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, "unknown-domain.example")
    service.record_manual_ownership(aid, analyst, "Signed letter")
    service.work_until_idle()
    statuses = {r["control_id"]: r["status"] for r in service.results(aid)}
    assert statuses["EML-01"] == statuses["EAS-04"] == statuses["TLS-01"] == "inconclusive"
    assert "fail" not in statuses.values()


# Gates ------------------------------------------------------------------------
def test_services_and_vulns_wait_for_their_approvals(live):
    service = live.extensions["runner"]
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, DOMAIN)
    assert service.check_ownership(aid)[0] is True
    service.work_until_idle()
    with pytest.raises(GateClosed, match="heads-up"):
        service.enqueue(aid, "services", analyst)
    with pytest.raises(GateClosed, match="approval"):
        service.enqueue(aid, "vulns", analyst)
    service.record_approval(aid, analyst, "Provider approval ref 42")
    with pytest.raises(GateClosed, match="report"):
        service.enqueue(aid, "vulns", analyst)
    with pytest.raises(ValueError):
        service.confirm_headsup(aid, analyst, "", ["192.0.2.10"])
    service.confirm_headsup(aid, analyst, "Told the host by email", ["192.0.2.10"])
    service.work_until_idle()
    results = {r["control_id"]: r for r in service.results(aid)}
    assert results["SVC-02"]["status"] == "fail"           # MySQL 3306
    assert results["SVC-03"]["needs_review"] == 1         # port 21 open in pass one only
    assert results["SVC-05"]["status"] == "pass"           # FTP was not confirmed
    assert results["LCY-02"]["status"] == "fail"           # MySQL 5.7 is end-of-life
    assert results["VUL-01"]["status"] == "not_tested"


# Review, sign-off, separation of duties ------------------------------------
def _ready(service, analyst_email="an@x.example"):
    a = service.db.one("SELECT * FROM users WHERE email = ?", (analyst_email,))
    cid = service.db.one("SELECT id FROM clients")["id"]
    aid = service.create_assessment(a, cid, DOMAIN)
    service.check_ownership(aid, a)
    service.work_until_idle()
    return aid


def _clear_flags(service, aid, reviewer):
    for row in service.results(aid):
        if row["needs_review"] and not row["reviewed_at"]:
            status = "pass" if row["status"] in ("review", "inconclusive") else row["status"]
            service.review_result(aid, row["control_id"], reviewer, status, "checked by hand")


def test_change_needs_a_note_and_signoff_waits_for_flags(live):
    service = live.extensions["runner"]
    add_people(service, ("an@x.example", ["analyst"]), ("rv@x.example", ["reviewer"]))
    aid = _ready(service)
    reviewer = service.db.one("SELECT * FROM users WHERE email = 'rv@x.example'")
    with pytest.raises(ValueError, match="note"):
        service.review_result(aid, "WEB-01", reviewer, "pass", "")
    with pytest.raises(ValueError, match="flagged"):
        service.sign_off(aid, reviewer, "")
    _clear_flags(service, aid, reviewer)
    service.sign_off(aid, reviewer, "")
    a = service.assessment(aid)
    assert a["status"] == "signed_off" and a["self_signoff"] == 0
    with pytest.raises(ValueError, match="locked"):
        service.review_result(aid, "WEB-01", reviewer, "pass", "late change")
    with pytest.raises(GateClosed):
        service.enqueue(aid, "web", reviewer)
    kinds = {n["kind"] for n in service.db.all("SELECT kind FROM notifications")}
    assert {"ownership_verified", "ready_for_review", "signed_off"} <= kinds


def test_reviewer_who_ran_it_cannot_sign_off_when_another_reviewer_exists(live):
    service = live.extensions["runner"]
    add_people(service, ("both@x.example", ["analyst", "reviewer"]), ("rv@x.example", ["reviewer"]))
    aid = _ready(service, "both@x.example")
    both = service.db.one("SELECT * FROM users WHERE email = 'both@x.example'")
    _clear_flags(service, aid, both)
    with pytest.raises(ValueError, match="Another reviewer"):
        service.sign_off(aid, both, "")
    other = service.db.one("SELECT * FROM users WHERE email = 'rv@x.example'")
    service.sign_off(aid, other, "")
    assert service.assessment(aid)["signed_off_by"] == other["id"]


def test_sole_reviewer_may_self_sign_off_and_it_is_audited(live):
    service = live.extensions["runner"]
    add_people(service)
    # The bootstrap admin holds all three staff roles and is the only reviewer.
    boss = service.db.one("SELECT * FROM users WHERE email = ?", (ADMIN[0],))
    assert set(boss["roles"].split(",")) == {"admin", "analyst", "reviewer"}
    aid = _ready(service, ADMIN[0])
    _clear_flags(service, aid, boss)
    service.sign_off(aid, boss, "")
    assert service.assessment(aid)["self_signoff"] == 1
    row = service.db.one("SELECT * FROM audit WHERE action = 'assessment.signed_off'")
    assert json.loads(row["detail"])["self_signoff"] is True


# Web: roles, CSRF, client visibility -----------------------------------------
def test_demo_logins_and_pages_render(demo):
    for email, password in [("admin@demo.example", "demo-admin"), ("analyst@demo.example", "demo-analyst"),
                            ("reviewer@demo.example", "demo-reviewer")]:
        c = demo.test_client()
        assert login(c, email, password).status_code == 302
        for url in ("/", "/assessments/1", "/assessments/2", "/assessments/1/report", "/assessments/2/report",
                    "/assessments/1/report.json", "/account"):
            assert c.get(url).status_code == 200, (email, url)
    c = demo.test_client()
    login(c, "admin@demo.example", "demo-admin")
    for url in ("/admin/people", "/admin/audit", "/admin/notifications", "/admin/audit?assessment=1"):
        assert c.get(url).status_code == 200
    assert "Hash chain intact" in c.get("/admin/audit").get_data(as_text=True)


def test_admin_cannot_run_or_sign_off(demo):
    c = demo.test_client()
    login(c, "admin@demo.example", "demo-admin")
    assert c.get("/assessments/new").status_code == 403
    assert post(c, "/assessments/2/signoff").status_code == 403
    assert post(c, "/assessments/2/rerun/web").status_code == 403
    assert post(c, "/assessments/2/review/WEB-02", status="pass", note="x").status_code == 403


def test_client_sees_results_only_after_signoff(demo):
    c = demo.test_client()
    login(c, f"client@{DOMAIN}", "demo-client")
    signed = c.get("/assessments/1/report").get_data(as_text=True)
    assert "External CyberHealth Check" in signed and "DRAFT" not in signed
    pending = c.get("/assessments/2/report").get_data(as_text=True)
    assert "after a reviewer" in pending and "SVC-01" not in pending
    assert c.get("/assessments/2/report.json").status_code == 404
    assert c.get("/assessments/1/evidence/1").status_code == 403
    assert c.get("/admin/audit").status_code == 403
    assert c.get("/assessments/2").status_code == 302  # clients go to the report view


def test_client_cannot_see_other_clients(demo):
    service = demo.extensions["runner"]
    other = service.db.run("INSERT INTO clients (name, created_at) VALUES ('Other', 'x')")
    accounts.create_user(service.db, "o@other.example", "O", "a-long-password", ["client"], client_id=other)
    c = demo.test_client()
    login(c, "o@other.example", "a-long-password")
    assert c.get("/assessments/1/report").status_code == 404
    assert "client-example.com" not in c.get("/").get_data(as_text=True)


def test_post_without_csrf_is_refused(demo):
    c = demo.test_client()
    login(c, "analyst@demo.example", "demo-analyst")
    assert c.post("/assessments/2/rerun/web").status_code == 400


def test_full_web_flow_review_and_signoff(demo):
    c = demo.test_client()
    login(c, "reviewer@demo.example", "demo-reviewer")
    page = c.get("/assessments/2").get_data(as_text=True)
    assert "flagged for a human decision" in page
    resp = post(c, "/assessments/2/review/WEB-02", status="pass", note="")
    assert "note is required" in c.get("/assessments/2").get_data(as_text=True)
    service = demo.extensions["runner"]
    for row in service.results(2):
        if row["needs_review"] and not row["reviewed_at"]:
            status = "pass" if row["status"] in ("review", "inconclusive") else row["status"]
            resp = post(c, f"/assessments/2/review/{row['control_id']}", status=status, note="looked at it")
            assert resp.status_code == 302
    post(c, "/assessments/2/signoff", note="ok")
    assert service.assessment(2)["status"] == "signed_off"
    client = demo.test_client()
    login(client, f"client@{DOMAIN}", "demo-client")
    assert "DRAFT" not in client.get("/assessments/2/report").get_data(as_text=True)


def test_analyst_creates_assessment_via_web(demo):
    c = demo.test_client()
    login(c, "analyst@demo.example", "demo-analyst")
    resp = post(c, "/assessments/new", client_id="1", target="new-client.example")
    assert resp.status_code == 302
    page = c.get(resp.headers["Location"]).get_data(as_text=True)
    assert "_cyberhealth.new-client.example" in page and "cyberhealth-verify=chk-" in page


def test_greenbone_upload_rejects_non_xml(demo):
    import io
    c = demo.test_client()
    login(c, "analyst@demo.example", "demo-analyst")
    data = {"csrf": csrf_of(c), "report": (io.BytesIO(b"not xml"), "report.xml")}
    c.post("/assessments/2/report-upload", data=data, content_type="multipart/form-data")
    assert demo.extensions["runner"].assessment(2)["report_file"] is None


def test_login_lockout(live):
    c = live.test_client()
    for _ in range(accounts.MAX_FAILURES):
        login(c, ADMIN[0], "wrong")
    resp = login(c, ADMIN[0], ADMIN[1])
    assert resp.status_code == 200 and "Too many" in resp.get_data(as_text=True)


# Audit and evidence ------------------------------------------------------------
def test_audit_chain_detects_tampering(demo):
    db = demo.extensions["runner"].db
    assert audit.verify_chain(db) == (True, None)
    db.run("UPDATE audit SET actor = 'someone-else' WHERE id = 3")
    assert audit.verify_chain(db) == (False, 3)


def test_evidence_files_match_their_hashes(demo):
    import hashlib
    for run in demo.extensions["runner"].db.all("SELECT * FROM module_runs WHERE status = 'done'"):
        assert hashlib.sha256(Path(run["evidence_path"]).read_bytes()).hexdigest() == run["evidence_sha256"]


def test_demo_signed_off_assessment_is_scored(demo):
    a = demo.extensions["runner"].assessment(1)
    score = json.loads(a["score_json"])
    assert a["status"] == "signed_off" and score["grade"] == "F" and score["coverage"] == 100
    assert any("Known exploited" in cap for cap in score["caps"])


# Parsers and individual checks ----------------------------------------------
def test_greenbone_parser_skips_log_and_low_quality():
    findings = parse_greenbone((DEMO_DIR / "greenbone-sample.xml").read_text())
    names = [f["name"] for f in findings]
    assert len(findings) == 3
    assert not any("OS Detection" in n or "Backup File" in n for n in names)
    assert findings[0]["cves"] == ["CVE-2021-40438"] and findings[0]["severity"] == 9.0


def test_greenbone_parser_refuses_entities():
    evil = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><report>&x;</report>'
    with pytest.raises(Exception):
        parse_greenbone(evil)


def test_nmap_parser():
    hosts = parse_nmap((DEMO_DIR / "nmap-pass2.xml").read_text())
    assert hosts["192.0.2.10"][3306]["product"] == "MySQL"
    assert hosts["192.0.2.10"][21]["state"] == "filtered"


class _Cfg:
    max_web_hosts = 10
    cache_dir = "/nonexistent"


def _ctx(net, target=DOMAIN):
    return Context(assessment={"target": target, "target_type": "domain"}, net=net, config=_Cfg())


def test_tls_weak_ciphers_inconclusive_when_openssl_cannot_test():
    results = {r["control_id"]: r for r in tls_check.run(_ctx(DemoNet()))}
    assert results["TLS-06"]["status"] == "inconclusive" and results["TLS-06"]["review"]
    assert "nmap" in results["TLS-06"]["summary"]


def test_spf_lookup_limit():
    class Net(DemoNet):
        def resolve(self, name, rtype):
            if rtype == "TXT" and name == DOMAIN:
                return ["v=spf1 " + " ".join(f"include:s{i}.mail.example" for i in range(11)) + " -all"]
            if rtype == "TXT" and name.endswith(".mail.example"):
                return ["v=spf1 ip4:198.51.100.1 -all"]
            if rtype == "MX":
                return ["mx.mail.example"]
            return []
    results = {r["control_id"]: r for r in email_check.run(_ctx(Net()))}
    assert results["EML-02"]["status"] == "fail" and "11" in results["EML-02"]["summary"]
    assert results["EML-03"]["status"] == "fail"


def test_eol_judgement():
    data, _ = eol.load()
    from datetime import date
    assert eol.judge("php", "7.4.3", data, today=date(2026, 1, 1))["status"] == "eol"
    assert eol.judge("php", "8.4.1", data, today=date(2026, 1, 1))["status"] == "supported"
    assert eol.judge("postgresql", "14.9", data, today=date(2026, 8, 1))["status"] == "soon"
    assert eol.judge("nginx", "9.9", data)["status"] == "unknown"
    assert eol.find_cycle(["1.1", "1.1.1"], "1.1.1") == "1.1.1"


def test_hanging_module_times_out_and_queue_moves_on(live, monkeypatch):
    import time as _time
    from runner import pipeline
    service = live.extensions["runner"]
    monkeypatch.setitem(pipeline.MODULE_TIMEOUT_MINUTES, "discovery", 0.01)  # 0.6 seconds

    def stuck(domain):
        _time.sleep(5)
        raise AssertionError("should have been abandoned")
    monkeypatch.setattr(service.net, "ct_names", stuck)
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, DOMAIN)
    service.check_ownership(aid)
    service.work_until_idle()
    runs = {r["module"]: r for r in service.runs(aid)}
    assert runs["discovery"]["status"] == "error" and "no result after" in runs["discovery"]["error"]
    assert "certificate transparency" in runs["discovery"]["error"]
    assert runs["tls"]["status"] == "done" and service.assessment(aid)["status"] == "in_review"
    statuses = {r["control_id"]: r["status"] for r in service.results(aid)}
    assert statuses["EAS-01"] == "inconclusive"


@pytest.mark.parametrize("text,expiry,locked", [
    ("Domain Name: bintara.com.my\nExpiry Date: 2027-03-10T00:00:00Z\nDomain Status: clientTransferProhibited\n",
     "2027-03-10", True),
    ("[Record Created]   10-Mar-2015\n[Record Expired]   10-Mar-2027\n", "2027-03-10", None),
    ("Registry Expiry Date: 2027-01-05\nDomain Status: ok https://icann.org/epp#ok\n", "2027-01-05", False),
    ("No match for domain\n", None, None),
])
def test_whois_parsing(text, expiry, locked):
    from runner.checks.brand import parse_whois
    got_expiry, got_locked = parse_whois(text)
    assert (got_expiry.date().isoformat() if got_expiry else None, got_locked) == (expiry, locked)


def test_registration_falls_back_to_whois_when_rdap_has_nothing():
    from runner.checks.brand import _registration_result
    from runner.net import NetError

    class Net(DemoNet):
        def rdap(self, domain):
            raise NetError("404 Not Found")

        def whois(self, domain, timeout=20):
            return "whois.mynic.my", "Expiry Date: 2099-01-01\nDomain Status: clientTransferProhibited\n"
    r = _registration_result(_ctx(Net(), "bintara.com.my"))
    assert r["status"] == "pass" and "WHOIS" in r["summary"]


def test_dnstwist_found_through_python_when_not_on_path(monkeypatch, tmp_path):
    import importlib.util
    import sys
    from runner.net import LiveNet
    net = LiveNet(load_config(data_dir=tmp_path, demo=False))
    monkeypatch.setattr(net, "which", lambda tool: None)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object() if name == "dnstwist" else None)
    assert net.tool_argv("dnstwist") == [sys.executable, "-m", "dnstwist"]
    assert net.tool_argv("nmap") is None


def test_known_hosts_parsing():
    assert ownership.parse_known_hosts("WWW.Example.com, mail.example.com\n*.shop.example.com", "example.com") == \
        ["*.shop.example.com", "mail.example.com", "www.example.com"]
    with pytest.raises(ValueError, match="other.com"):
        ownership.parse_known_hosts("www.example.com other.com", "example.com")
    assert ownership.host_is_known("a.shop.example.com", ["*.shop.example.com"])
    assert not ownership.host_is_known("shop.example.com.evil.com", ["*.shop.example.com"])


@pytest.mark.parametrize("known,status,flagged", [
    ("", "review", True),
    (f"{DOMAIN} www.{DOMAIN} mail.{DOMAIN}", "partial", True),     # dev and vpn are not on the list
    (f"{DOMAIN} *.{DOMAIN}", "pass", False),
])
def test_eas01_compares_with_client_list(live, known, status, flagged):
    service = live.extensions["runner"]
    cid, ids = add_people(service, ("an@x.example", ["analyst"]))
    analyst = service.user(ids["an@x.example"])
    aid = service.create_assessment(analyst, cid, DOMAIN, known)
    service.check_ownership(aid)
    service.work_until_idle()
    row = {r["control_id"]: r for r in service.results(aid)}["EAS-01"]
    assert (row["status"], bool(row["needs_review"])) == (status, flagged)
    if status == "partial":
        assert "dev.client-example.com" in row["summary"] and "vpn.client-example.com" in row["summary"]


def test_saving_known_hosts_reruns_discovery(demo):
    c = demo.test_client()
    login(c, "analyst@demo.example", "demo-analyst")
    post(c, "/assessments/2/known-hosts", known_hosts=f"{DOMAIN}\n*.{DOMAIN}")
    service = demo.extensions["runner"]
    assert service.runs(2)[0]["module"] == "discovery" and service.runs(2)[0]["status"] == "queued"
    service.work_until_idle()
    row = {r["control_id"]: r for r in service.results(2)}["EAS-01"]
    assert row["status"] == "pass"
    post(c, "/assessments/2/known-hosts", known_hosts="evil.example")
    assert "Not part of" in c.get("/assessments/2").get_data(as_text=True)


# Tiers and downloadable reports ---------------------------------------------------
def _download(c, url):
    resp = c.get(url)
    return resp.status_code, resp.data, resp.headers.get("Content-Disposition", "")


def test_admin_sets_client_tier(demo):
    c = demo.test_client()
    login(c, "admin@demo.example", "demo-admin")
    db = demo.extensions["runner"].db
    post(c, "/admin/organizations/1", action="save", name="Client Example Ltd (fictional)",
         contact_email=f"client@{DOMAIN}", tier="comprehensive")
    assert db.one("SELECT tier FROM clients WHERE id = 1")["tier"] == "comprehensive"
    assert db.one("SELECT * FROM audit WHERE action = 'client.tier_changed'")
    resp = post(c, "/admin/organizations", name="New Co", tier="comprehensive", contact_email="")
    new = db.one("SELECT * FROM clients WHERE name = 'New Co'")
    assert new["tier"] == "comprehensive" and resp.headers["Location"].endswith(f"/admin/organizations/{new['id']}")
    post(c, "/admin/organizations", name="new co", tier="complimentary")  # duplicate name refused
    assert db.one("SELECT COUNT(*) AS n FROM clients WHERE lower(name) = 'new co'")["n"] == 1


def test_organizations_pages_render_and_are_admin_only(demo):
    c = demo.test_client()
    login(c, "admin@demo.example", "demo-admin")
    page = c.get("/admin/organizations").get_data(as_text=True)
    assert "Client Example Ltd (fictional)" in page and "Complimentary" in page and "Manage" in page
    assert c.get("/admin/organizations?org=1").status_code == 200
    detail = c.get("/admin/organizations/1").get_data(as_text=True)
    assert DOMAIN in detail and "Organization access settings" in detail
    assert c.get("/admin/organizations/999").status_code == 404
    other = demo.test_client()
    login(other, "analyst@demo.example", "demo-analyst")
    assert other.get("/admin/organizations").status_code == 403


def test_suspended_organization_cannot_sign_in(demo):
    admin = demo.test_client()
    login(admin, "admin@demo.example", "demo-admin")
    client = demo.test_client()
    login(client, f"client@{DOMAIN}", "demo-client")
    assert client.get("/").status_code == 200
    post(admin, "/admin/organizations/1", action="suspend")
    assert client.get("/").status_code == 302               # existing session ends
    fresh = demo.test_client()
    resp = login(fresh, f"client@{DOMAIN}", "demo-client")
    assert resp.status_code == 200 and "suspended" in resp.get_data(as_text=True)
    post(admin, "/admin/organizations/1", action="reactivate")
    assert login(demo.test_client(), f"client@{DOMAIN}", "demo-client").status_code == 302


def test_client_downloads_only_own_tier_after_signoff(demo):
    c = demo.test_client()
    login(c, f"client@{DOMAIN}", "demo-client")
    status, body, disposition = _download(c, "/assessments/1/report.pdf?tier=comprehensive")
    assert status == 200 and body.startswith(b"%PDF") and "Complimentary" in disposition  # tier forced to client's own
    status, body, disposition = _download(c, "/assessments/1/report.pptx")
    assert status == 200 and body[:2] == b"PK" and disposition.endswith('.pptx"')
    assert c.get("/assessments/2/report.pdf").status_code == 404  # not signed off yet


def test_staff_download_either_tier_with_draft_marking(demo):
    import zipfile
    from io import BytesIO
    c = demo.test_client()
    login(c, "reviewer@demo.example", "demo-reviewer")
    for tier in ("complimentary", "comprehensive"):
        status, body, disposition = _download(c, f"/assessments/2/report.pdf?tier={tier}")
        assert status == 200 and body.startswith(b"%PDF") and tier.title() in disposition
        status, body, _ = _download(c, f"/assessments/2/report.pptx?tier={tier}")
        slides = zipfile.ZipFile(BytesIO(body)).namelist()
        assert sum(n.startswith("ppt/slides/slide") for n in slides) >= (8 if tier == "comprehensive" else 5)
    assert c.get("/assessments/2/report.pdf?tier=gold").status_code == 400
    assert demo.extensions["runner"].db.one("SELECT * FROM audit WHERE action = 'report.downloaded'")


def test_report_summary_is_used(demo):
    from runner import reports
    c = demo.test_client()
    login(c, "reviewer@demo.example", "demo-reviewer")
    post(c, "/assessments/2/summary", summary_text="Hand-written summary for the board.")
    service = demo.extensions["runner"]
    data = reports.build(service, 2, "comprehensive")
    assert data["summary"] == "Hand-written summary for the board." and data["draft"]
    assert all(f["id"].startswith("F-") for f in data["findings"])
    severities = [reports.SEV_ORDER[f["severity"]] for f in data["findings"]]
    assert severities == sorted(severities)


def test_every_control_has_plain_wording():
    from runner.reports.plain import PLAIN
    assert set(PLAIN) == {c.id for c in CONTROLS}
    assert all(set(v) == {"finding", "impact", "action", "good"} for v in PLAIN.values())


# Domains and branding ----------------------------------------------------------
def _png(w=64, h=32, fmt="PNG"):
    from io import BytesIO
    from PIL import Image
    out = BytesIO()
    Image.new("RGB", (w, h), (14, 124, 134)).save(out, format=fmt)
    return out.getvalue()


def _upload(c, scope, logo=None, **fields):
    from io import BytesIO
    data = {"csrf": csrf_of(c), "scope": scope, **fields}
    if logo is not None:
        data["logo"] = (BytesIO(logo), "logo.png")
    return c.post("/admin/branding", data=data, content_type="multipart/form-data")


def test_domains_page_lists_and_filters(demo):
    c = demo.test_client()
    login(c, "reviewer@demo.example", "demo-reviewer")
    page = c.get("/admin/domains").get_data(as_text=True)
    assert DOMAIN in page and "domain(s)" in page and "Organization" in page
    assert "(1 domain)" in page or "domains)" in page
    assert DOMAIN not in c.get("/admin/domains?org=999").get_data(as_text=True).split("domain(s)")[1]
    client = demo.test_client()
    login(client, f"client@{DOMAIN}", "demo-client")
    assert client.get("/admin/domains").status_code == 403


@pytest.mark.parametrize("logo, message", [
    (b"not an image", "not a readable"),
    (_png(8, 8), "between 16 and 2048"),
    (_png(fmt="GIF"), "PNG or JPEG"),
    (b"\x89PNG" + b"0" * (2 * 1024 * 1024), "2 MB"),
])
def test_branding_rejects_bad_logos(demo, logo, message):
    c = demo.test_client()
    login(c, "admin@demo.example", "demo-admin")
    resp = _upload(c, "1", logo, brand_name="Partner")
    assert message in c.get(resp.headers["Location"]).get_data(as_text=True)
    assert demo.extensions["runner"].db.one("SELECT logo_file FROM clients WHERE id = 1")["logo_file"] is None


def test_org_branding_shows_for_its_users_reports_and_can_be_restored(demo):
    import zipfile
    from io import BytesIO
    from runner import reports
    from runner.reports import pdf, slides
    service = demo.extensions["runner"]
    admin = demo.test_client()
    login(admin, "admin@demo.example", "demo-admin")
    _upload(admin, "1", _png(), brand_name="Partner Security", restore="")
    org = service.db.one("SELECT * FROM clients WHERE id = 1")
    assert org["brand_name"] == "Partner Security" and org["logo_file"].startswith("org-1-")
    logo_url = f"/brand/logo/{org['logo_file']}"

    client = demo.test_client()
    login(client, f"client@{DOMAIN}", "demo-client")
    home = client.get("/").get_data(as_text=True)
    assert logo_url in home and "Partner Security" in home
    assert client.get(logo_url).status_code == 200
    assert demo.test_client().get(logo_url).status_code == 404  # not public

    data = reports.build(service, 1, "complimentary")
    assert data["brand"] == "Partner Security" and data["logo_path"].endswith(org["logo_file"])
    assert pdf.render(data).startswith(b"%PDF")
    deck = zipfile.ZipFile(BytesIO(slides.render(data)))
    assert any(n.startswith("ppt/media/") for n in deck.namelist())

    _upload(admin, "1", brand_name="", restore="1")
    org = service.db.one("SELECT * FROM clients WHERE id = 1")
    assert org["logo_file"] is None and not (service.config.branding_dir / Path(logo_url).name).exists()
    assert "Partner Security" not in client.get("/").get_data(as_text=True)


def test_platform_logo_is_public_and_admin_only_to_change(demo):
    admin = demo.test_client()
    login(admin, "admin@demo.example", "demo-admin")
    _upload(admin, "platform", _png(), brand_name="")
    name = demo.extensions["runner"].db.one("SELECT value FROM settings WHERE key = 'logo_file'")["value"]
    anon = demo.test_client()
    assert f"/brand/logo/{name}" in anon.get("/login").get_data(as_text=True)
    assert anon.get(f"/brand/logo/{name}").status_code == 200
    reviewer = demo.test_client()
    login(reviewer, "reviewer@demo.example", "demo-reviewer")
    assert reviewer.get("/admin/branding").status_code == 403
    assert admin.get("/admin/branding?scope=1").status_code == 200
