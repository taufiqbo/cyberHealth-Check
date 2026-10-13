"""CyberHealth Runner web app."""
import os
import secrets
import shutil
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from runner import accounts, audit, ownership, scoring
from runner.checks.vulns import parse_greenbone
from runner.config import load_config
from runner.controls import BY_ID, MODULES, REVIEWER_CHOICES, STATUS_LABELS
from runner.db import Database, loads
from runner.pipeline import GateClosed, Service, Worker, gate
from runner.reports import TIERS

UPLOAD_TYPES = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".eml", ".msg", ".docx", ".xml"}
STATUS_TEXT = {"awaiting_ownership": "Waiting for ownership proof", "running": "Checks running",
               "in_review": "In review", "signed_off": "Signed off"}


def create_app(config=None, net=None, start_worker=None):
    config = config or load_config()
    if config.demo:
        demo_reset(config)
    db = Database(config.db_path)
    if net is None:
        if config.demo:
            from runner.demo_net import DemoNet
            net = DemoNet(token_lookup=lambda domain: [r["ownership_token"] for r in db.all(
                "SELECT ownership_token FROM assessments WHERE target = ?", (domain,))])
        else:
            from runner.net import LiveNet
            net = LiveNet(config)
    service = Service(db, config, net)
    if config.demo and not db.one("SELECT id FROM users LIMIT 1"):
        from runner.demo_seed import seed
        seed(service)
    else:
        accounts.bootstrap_admin(db, config)

    app = Flask(__name__)
    app.config.update(SECRET_KEY=config.secret_key, MAX_CONTENT_LENGTH=50 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=config.secure_cookies)
    app.extensions["runner"] = service
    app.jinja_env.globals.update(STATUS_LABELS=STATUS_LABELS, STATUS_TEXT=STATUS_TEXT, MODULES=MODULES,
                                 BY_ID=BY_ID, DEMO=config.demo, SCORE_VERSION=scoring.VERSION,
                                 SCAN_IP=config.scan_ip, BRAND=config.brand_name,
                                 BRAND_TAGLINE=config.brand_tagline, BRAND_CONTACT=config.brand_contact)

    if start_worker is None:
        start_worker = config.inline_worker
    if start_worker:
        Worker(service).start()

    register(app, service)
    return app


def demo_reset(config):
    """Demo starts clean every time."""
    for path in (config.db_path, Path(str(config.db_path) + "-wal"), Path(str(config.db_path) + "-shm")):
        if Path(path).exists():
            Path(path).unlink()
    for d in (config.evidence_dir, config.uploads_dir):
        shutil.rmtree(d, ignore_errors=True)
        Path(d).mkdir(parents=True, exist_ok=True)


def register(app, service):
    db, config = service.db, service.config

    # Session, roles, CSRF ---------------------------------------------------
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid:
            user = db.one("SELECT * FROM users WHERE id = ? AND active = 1", (uid,))
            if user:
                g.user = user
                g.roles = accounts.roles_of(user)
            else:
                session.clear()
        if request.method == "POST":
            token = session.get("csrf")
            if not token or request.form.get("csrf") != token:
                abort(400, "The form expired. Go back, reload the page and try again.")

    @app.after_request
    def headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "script-src 'self'; frame-ancestors 'none'")
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return resp

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf": session["csrf"], "user": g.get("user"), "roles": g.get("roles", set())}

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for("login", next=request.path))
            return fn(*a, **kw)
        return wrapper

    def role_required(*allowed):
        def deco(fn):
            @wraps(fn)
            @login_required
            def wrapper(*a, **kw):
                if not g.roles & set(allowed):
                    abort(403)
                return fn(*a, **kw)
            return wrapper
        return deco

    def is_staff():
        return bool(g.roles & set(accounts.STAFF_ROLES))

    def load_assessment(aid):
        a = service.assessment(aid)
        if not a:
            abort(404)
        if not is_staff() and a["client_id"] != g.user["client_id"]:
            abort(404)
        return a

    def save_upload(aid, field, required=False, allowed=UPLOAD_TYPES):
        file = request.files.get(field)
        if not file or not file.filename:
            if required:
                raise ValueError("Choose a file to upload.")
            return None
        name = secure_filename(file.filename) or "upload"
        if Path(name).suffix.lower() not in allowed:
            raise ValueError(f"That file type is not accepted ({', '.join(sorted(allowed))}).")
        folder = Path(config.uploads_dir) / str(aid)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{uuid.uuid4().hex[:8]}-{name}"
        file.save(path)
        return str(path)

    # Sign-in ------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user, error = accounts.authenticate(db, request.form.get("email"), request.form.get("password"))
            if user:
                session.clear()
                session["uid"] = user["id"]
                session["csrf"] = secrets.token_urlsafe(32)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("home"))
            flash(error, "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        if request.method == "POST":
            if not check_password_hash(g.user["password_hash"], request.form.get("current") or ""):
                flash("Your current password is wrong.", "error")
            elif request.form.get("new") != request.form.get("confirm"):
                flash("The new passwords do not match.", "error")
            else:
                try:
                    accounts.set_password(db, g.user["id"], request.form.get("new"), g.user)
                    flash("Password changed.", "ok")
                except ValueError as exc:
                    flash(str(exc), "error")
        return render_template("account.html")

    @app.route("/healthz")
    def healthz():
        return {"ok": True, "demo": config.demo}

    # Home ---------------------------------------------------------------------
    @app.route("/")
    @login_required
    def home():
        if is_staff():
            rows = db.all("SELECT a.*, c.name AS client_name FROM assessments a JOIN clients c ON c.id = a.client_id"
                          " ORDER BY a.id DESC")
        else:
            rows = db.all("SELECT a.*, c.name AS client_name FROM assessments a JOIN clients c ON c.id = a.client_id"
                          " WHERE a.client_id = ? ORDER BY a.id DESC", (g.user["client_id"],))
        for a in rows:
            a["flagged"] = db.one("SELECT COUNT(*) AS n FROM results WHERE assessment_id = ? AND needs_review = 1",
                                  (a["id"],))["n"]
            a["score"] = loads(a["score_json"]) if a["signed_off_at"] else None
        my_client = None if is_staff() else db.one("SELECT * FROM clients WHERE id = ?", (g.user["client_id"],))
        return render_template("home.html", assessments=rows, my_client=my_client, tiers=TIERS)

    # Assessments --------------------------------------------------------------
    @app.route("/assessments/new", methods=["GET", "POST"])
    @role_required("analyst")
    def new_assessment():
        clients = db.all("SELECT * FROM clients ORDER BY name")
        if request.method == "POST":
            try:
                client_id = int(request.form.get("client_id") or 0)
                if not db.one("SELECT id FROM clients WHERE id = ?", (client_id,)):
                    raise ValueError("Choose a client.")
                aid = service.create_assessment(g.user, client_id, request.form.get("target"),
                                                request.form.get("known_hosts", ""))
                service.check_ownership(aid, g.user)
                return redirect(url_for("assessment", aid=aid))
            except ValueError as exc:
                flash(str(exc), "error")
        return render_template("new.html", clients=clients)

    @app.route("/assessments/<int:aid>")
    @login_required
    def assessment(aid):
        a = load_assessment(aid)
        if not is_staff():
            return redirect(url_for("report", aid=aid))
        client = db.one("SELECT * FROM clients WHERE id = ?", (a["client_id"],))
        results = service.results(aid)
        by_module = {m: [r for r in results if r["module"] == m] for m in MODULES}
        states = service.module_states(a)
        disc = service.prior_evidence(aid).get("discovery", {})
        allowed, self_signoff, why_not = (service.signoff_check(aid, g.user) if "reviewer" in g.roles
                                          else (False, False, "Only a reviewer can sign off."))
        people = {u["id"]: u for u in db.all("SELECT id, name, email FROM users")}
        return render_template(
            "assessment.html", a=a, client=client, by_module=by_module, states=states,
            score=loads(a["score_json"]) if a["signed_off_at"] else service.score(aid),
            steps=ownership.instructions(a), scan_scope=disc.get("scan_scope", []),
            headsup_scope=loads(a["headsup_scope"], []), runs=service.runs(aid)[:30],
            known_hosts=loads(a["known_hosts"], []),
            live_hosts=[h["name"] for h in disc.get("hosts", []) if h.get("resolves")],
            can_signoff=allowed, self_signoff=self_signoff, why_not=why_not, people=people,
            flagged=[r for r in results if r["needs_review"] and not r["reviewed_at"]],
            choices=REVIEWER_CHOICES, tiers=TIERS)

    @app.route("/assessments/<int:aid>/ownership/check", methods=["POST"])
    @role_required("analyst")
    def ownership_check(aid):
        load_assessment(aid)
        verified, message = service.check_ownership(aid, g.user)
        flash(message, "ok" if verified else "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/ownership/manual", methods=["POST"])
    @role_required("analyst")
    def ownership_manual(aid):
        a = load_assessment(aid)
        try:
            if a["ownership_verified_at"]:
                raise ValueError("Ownership is already proven.")
            path = save_upload(aid, "file")
            service.record_manual_ownership(aid, g.user, request.form.get("note", ""), path)
            flash("Ownership proof recorded. The automatic checks have started.", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/known-hosts", methods=["POST"])
    @role_required("analyst")
    def known_hosts(aid):
        load_assessment(aid)
        try:
            known = service.set_known_hosts(aid, g.user, request.form.get("known_hosts", ""))
            flash(f"Client asset list saved ({len(known)} name(s)). Discovery will compare against it.", "ok")
        except (ValueError, GateClosed) as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/headsup", methods=["POST"])
    @role_required("analyst")
    def headsup(aid):
        load_assessment(aid)
        raw = request.form.get("scope", "")
        scope = []
        try:
            for item in raw.replace(",", " ").split():
                ip, _ = ownership.normalise_target(item, allow_private=config.demo)
                if _ != "ip":
                    raise ValueError(f"{item} is not an IP address.")
                if ip not in scope:
                    scope.append(ip)
            if len(scope) > config.max_scan_hosts:
                raise ValueError(f"At most {config.max_scan_hosts} addresses per assessment.")
            service.confirm_headsup(aid, g.user, request.form.get("note", ""), scope)
            flash("Heads-up confirmed. Nmap is queued.", "ok")
        except (ValueError, GateClosed) as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/approval", methods=["POST"])
    @role_required("analyst")
    def approval(aid):
        load_assessment(aid)
        try:
            path = save_upload(aid, "file")
            service.record_approval(aid, g.user, request.form.get("note", ""), path)
            flash("Written approval recorded.", "ok")
        except (ValueError, GateClosed) as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/report-upload", methods=["POST"])
    @role_required("analyst")
    def report_upload(aid):
        load_assessment(aid)
        try:
            path = save_upload(aid, "report", required=True, allowed={".xml"})
            try:
                findings = parse_greenbone(Path(path).read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                os.unlink(path)
                raise ValueError(f"That is not a readable Greenbone/OpenVAS XML report ({exc.__class__.__name__}).")
            service.record_report(aid, g.user, path)
            flash(f"Report uploaded: {len(findings)} finding(s) above log level.", "ok")
        except (ValueError, GateClosed) as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/rerun/<module>", methods=["POST"])
    @role_required("analyst")
    def rerun(aid, module):
        load_assessment(aid)
        if module not in MODULES:
            abort(404)
        try:
            service.enqueue(aid, module, g.user)
            flash(f"{MODULES[module]} queued.", "ok")
        except GateClosed as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/review/<control_id>", methods=["POST"])
    @role_required("reviewer")
    def review(aid, control_id):
        load_assessment(aid)
        status = request.form.get("status")
        if control_id not in BY_ID or status not in REVIEWER_CHOICES:
            abort(400)
        try:
            service.review_result(aid, control_id, g.user, status, request.form.get("note", ""))
            flash(f"{control_id} saved.", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid) + f"#{control_id}")

    @app.route("/assessments/<int:aid>/signoff", methods=["POST"])
    @role_required("reviewer")
    def signoff(aid):
        load_assessment(aid)
        try:
            service.sign_off(aid, g.user, request.form.get("note", ""))
            flash("Signed off. The client has been notified.", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("assessment", aid=aid))

    @app.route("/assessments/<int:aid>/evidence/<int:run_id>")
    @role_required("admin", "analyst", "reviewer")
    def evidence(aid, run_id):
        load_assessment(aid)
        run = db.one("SELECT * FROM module_runs WHERE id = ? AND assessment_id = ?", (run_id, aid))
        if not run or not run["evidence_path"]:
            abort(404)
        path = Path(run["evidence_path"]).resolve()
        if not path.is_relative_to(Path(config.evidence_dir).resolve()) or not path.exists():
            abort(404)
        return send_file(path, mimetype="application/json", as_attachment=True, download_name=path.name)

    def report_data(aid):
        a = load_assessment(aid)
        if not is_staff() and not a["signed_off_at"]:
            return a, None, None
        results = service.results(aid)
        score = loads(a["score_json"]) if a["signed_off_at"] else service.score(aid)
        return a, results, score

    @app.route("/assessments/<int:aid>/report")
    @login_required
    def report(aid):
        a, results, score = report_data(aid)
        client = db.one("SELECT * FROM clients WHERE id = ?", (a["client_id"],))
        signer = service.user(a["signed_off_by"])
        if results is None:
            return render_template("report_pending.html", a=a, client=client)
        by_module = {m: [r for r in results if r["module"] == m] for m in MODULES}
        return render_template("report.html", a=a, client=client, by_module=by_module, score=score, signer=signer,
                               tiers=TIERS)

    @app.route("/assessments/<int:aid>/summary", methods=["POST"])
    @role_required("analyst", "reviewer")
    def report_summary(aid):
        a = load_assessment(aid)
        if a["signed_off_at"]:
            flash("This assessment is signed off and locked.", "error")
        else:
            text = request.form.get("summary_text", "").strip()[:4000]
            db.update("assessments", aid, summary_text=text or None)
            audit.record(db, "report.summary_edited", g.user, aid, length=len(text))
            flash("Report summary saved." if text else "Report summary cleared; the automatic summary will be used.", "ok")
        return redirect(url_for("assessment", aid=aid) + "#summary")

    def download_tier(a):
        """Clients get their own tier, and only after sign-off. Staff may pick either tier, any time."""
        client = db.one("SELECT * FROM clients WHERE id = ?", (a["client_id"],))
        if not is_staff():
            if not a["signed_off_at"]:
                abort(404)
            return client["tier"]
        tier = request.args.get("tier") or client["tier"]
        if tier not in TIERS:
            abort(400)
        return tier

    @app.route("/assessments/<int:aid>/report.<fmt>")
    @login_required
    def report_file(aid, fmt):
        if fmt not in ("pdf", "pptx"):
            abort(404)
        a = load_assessment(aid)
        tier = download_tier(a)
        from runner import reports
        data = reports.build(service, aid, tier)
        if fmt == "pdf":
            from runner.reports import pdf
            body, mime = pdf.render(data), "application/pdf"
        else:
            from runner.reports import slides
            body = slides.render(data)
            mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        audit.record(db, "report.downloaded", g.user, aid, format=fmt, tier=tier, draft=data["draft"])
        resp = app.response_class(body, mimetype=mime)
        resp.headers["Content-Disposition"] = f'attachment; filename="{reports.filename(data, fmt)}"'
        return resp

    @app.route("/assessments/<int:aid>/report.json")
    @login_required
    def report_json(aid):
        a, results, score = report_data(aid)
        if results is None:
            abort(404)
        return jsonify({
            "target": a["target"], "signed_off_at": a["signed_off_at"], "draft": not a["signed_off_at"],
            "score": score,
            "controls": [{"id": r["control_id"], "title": BY_ID[r["control_id"]].title,
                          "severity": BY_ID[r["control_id"]].severity, "status": r["status"],
                          "summary": r["summary"], "review_note": r["review_note"]} for r in results],
        })

    # Admin -------------------------------------------------------------------
    @app.route("/admin/people", methods=["GET", "POST"])
    @role_required("admin")
    def people():
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "add_client":
                    name = request.form.get("name", "").strip()
                    if not name:
                        raise ValueError("Enter the client's name.")
                    tier = request.form.get("tier", "complimentary")
                    if tier not in TIERS:
                        raise ValueError("Choose a tier.")
                    cid = db.run("INSERT INTO clients (name, contact_email, created_at, tier) VALUES (?, ?, datetime('now'), ?)",
                                 (name, request.form.get("contact_email", "").strip().lower() or None, tier))
                    audit.record(db, "client.created", g.user, None, client_id=cid, name=name, tier=tier)
                    flash(f"Client {name} added.", "ok")
                elif action == "add_user":
                    accounts.create_user(db, request.form.get("email"), request.form.get("name", ""),
                                         request.form.get("password"), request.form.getlist("roles"),
                                         int(request.form.get("client_id") or 0) or None, actor=g.user)
                    flash("Person added.", "ok")
                elif action in ("deactivate", "activate"):
                    uid = int(request.form.get("user_id"))
                    if uid == g.user["id"]:
                        raise ValueError("You cannot deactivate yourself.")
                    db.update("users", uid, active=1 if action == "activate" else 0)
                    target = service.user(uid)
                    audit.record(db, f"user.{action}d", g.user, None, user=target["email"])
                    flash(f"{target['email']} {action}d.", "ok")
                elif action == "set_tier":
                    cid = int(request.form.get("client_id"))
                    tier = request.form.get("tier")
                    client = db.one("SELECT * FROM clients WHERE id = ?", (cid,))
                    if not client or tier not in TIERS:
                        raise ValueError("Choose a client and a tier.")
                    db.update("clients", cid, tier=tier)
                    audit.record(db, "client.tier_changed", g.user, None, client_id=cid, name=client["name"],
                                 before=client["tier"], after=tier)
                    flash(f"{client['name']} is now on the {TIERS[tier]} tier.", "ok")
                elif action == "reset_password":
                    uid = int(request.form.get("user_id"))
                    accounts.set_password(db, uid, request.form.get("password"), g.user)
                    flash("Password reset.", "ok")
            except ValueError as exc:
                flash(str(exc), "error")
            return redirect(url_for("people"))
        users = db.all("SELECT u.*, c.name AS client_name FROM users u LEFT JOIN clients c ON c.id = u.client_id"
                       " ORDER BY u.active DESC, u.email")
        clients = db.all("SELECT * FROM clients ORDER BY name")
        return render_template("people.html", users=users, clients=clients, all_roles=accounts.ALL_ROLES, tiers=TIERS)

    @app.route("/admin/audit")
    @role_required("admin")
    def audit_view():
        aid = request.args.get("assessment", type=int)
        if aid:
            rows = db.all("SELECT * FROM audit WHERE assessment_id = ? ORDER BY id DESC", (aid,))
        else:
            rows = db.all("SELECT * FROM audit ORDER BY id DESC LIMIT 500")
        ok, bad = audit.verify_chain(db)
        return render_template("audit.html", rows=rows, chain_ok=ok, bad_id=bad, aid=aid)

    @app.route("/admin/notifications")
    @role_required("admin")
    def notifications():
        rows = db.all("SELECT * FROM notifications ORDER BY id DESC LIMIT 300")
        return render_template("notifications.html", rows=rows)

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def error(exc):
        return render_template("error.html", error=exc), exc.code


if __name__ == "__main__":
    application = create_app()
    application.run(host=os.environ.get("RUNNER_BIND", "127.0.0.1"), port=int(os.environ.get("PORT", 8000)),
                    debug=False, threaded=True)
