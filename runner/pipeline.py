"""Orchestration: gates, the job queue, review and sign-off rules."""
import hashlib
import json
import threading
import time
import traceback
from datetime import timedelta
from pathlib import Path

from . import audit, notify, ownership, scoring
from .checks import Context, get_runner
from .controls import BY_ID, MODULES, for_module
from .db import dumps, loads, now, parse_time

AUTO_MODULES = ["discovery", "tls", "email", "web", "brand", "lifecycle"]
# Lifecycle reads what the others collected, so it always goes last.
ORDER = ["discovery", "tls", "email", "web", "brand", "services", "vulns", "lifecycle"]
DNS_MODULES = {"discovery", "tls", "email", "web", "brand"}
# Longest a module may run before the worker gives up on it and moves to the next job (minutes).
MODULE_TIMEOUT_MINUTES = {"discovery": 20, "tls": 15, "email": 5, "web": 10, "brand": 40,
                          "services": 90, "lifecycle": 5, "vulns": 30}


class ModuleTimeout(Exception):
    pass


def log(message):
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


class GateClosed(Exception):
    pass


def gate(assessment, module):
    """Returns None if the module may run, or the reason it must wait."""
    owned = bool(assessment.get("ownership_verified_at"))
    if module == "lifecycle":
        return None
    if not owned:
        return "Waiting for ownership proof."
    if module == "services":
        if not assessment.get("headsup_at"):
            return "Waiting for the hosting provider heads-up to be confirmed."
        if not loads(assessment.get("headsup_scope"), []):
            return "The confirmed scan scope is empty."
    if module == "vulns":
        if not assessment.get("approval_at"):
            return "Waiting for written provider approval."
        if not assessment.get("report_file"):
            return "Waiting for the Greenbone/OpenVAS XML report."
    return None


class Service:
    def __init__(self, db, config, net):
        self.db = db
        self.config = config
        self.net = net
        self._lock = threading.Lock()

    # Lookups ----------------------------------------------------------------
    def assessment(self, assessment_id):
        return self.db.one("SELECT * FROM assessments WHERE id = ?", (assessment_id,))

    def user(self, user_id):
        return self.db.one("SELECT * FROM users WHERE id = ?", (user_id,)) if user_id else None

    def users_with_role(self, role):
        return [u for u in self.db.all("SELECT * FROM users WHERE active = 1")
                if role in u["roles"].split(",")]

    def results(self, assessment_id):
        rows = self.db.all("SELECT * FROM results WHERE assessment_id = ?", (assessment_id,))
        by_id = {r["control_id"]: r for r in rows}
        out = []
        for control_id, control in BY_ID.items():
            row = by_id.get(control_id) or {
                "control_id": control_id, "module": control.module, "status": "not_tested",
                "original_status": "not_tested", "summary": "Not run yet.", "details": None,
                "needs_review": 0, "reviewed_by": None, "review_note": None, "reviewed_at": None,
            }
            row = dict(row)
            row["details_obj"] = loads(row.get("details"), {})
            out.append(row)
        return out

    def score(self, assessment_id):
        return scoring.compute(self.results(assessment_id))

    def runs(self, assessment_id):
        return self.db.all("SELECT * FROM module_runs WHERE assessment_id = ? ORDER BY id DESC", (assessment_id,))

    def module_states(self, assessment):
        runs = self.runs(assessment["id"])
        states = {}
        for module, label in MODULES.items():
            mine = [r for r in runs if r["module"] == module]
            latest = next((r for r in mine if r["status"] == "running"), mine[0] if mine else None)
            states[module] = {"label": label, "latest": latest, "gate": gate(assessment, module)}
        return states

    def prior_evidence(self, assessment_id):
        prior = {}
        for module in MODULES:
            run = self.db.one("SELECT * FROM module_runs WHERE assessment_id = ? AND module = ? AND status = 'done'"
                              " ORDER BY id DESC LIMIT 1", (assessment_id, module))
            if run and run["evidence_path"] and Path(run["evidence_path"]).exists():
                prior[module] = json.loads(Path(run["evidence_path"]).read_text()).get("data", {})
        return prior

    def involvement(self, assessment):
        """User ids who ran or approved parts of this assessment."""
        ids = {assessment["created_by"], assessment.get("headsup_by"), assessment.get("approval_by"),
               assessment.get("report_by")}
        if assessment.get("ownership_method") == "manual":
            ids.add(assessment.get("ownership_verified_by"))
        for run in self.runs(assessment["id"]):
            ids.add(run["triggered_by"])
        return {i for i in ids if i}

    # Assessment lifecycle ----------------------------------------------------
    def create_assessment(self, actor, client_id, raw_target, known_hosts_text=""):
        target, target_type = ownership.normalise_target(raw_target, allow_private=self.config.demo)
        known = ownership.parse_known_hosts(known_hosts_text, target) if target_type == "domain" else []
        aid = self.db.run(
            "INSERT INTO assessments (client_id, target, target_type, status, created_by, created_at, ownership_token,"
            " known_hosts) VALUES (?, ?, ?, 'awaiting_ownership', ?, ?, ?, ?)",
            (client_id, target, target_type, actor["id"], now(), ownership.new_token(),
             dumps(known) if known else None))
        audit.record(self.db, "assessment.created", actor, aid, target=target, client_id=client_id,
                     known_hosts=len(known))
        return aid

    def set_known_hosts(self, assessment_id, actor, text):
        """The client's own list of host names. Discovery compares what it finds against it (EAS-01)."""
        a = self.assessment(assessment_id)
        if a["signed_off_at"]:
            raise ValueError("This assessment is signed off and locked.")
        known = ownership.parse_known_hosts(text, a["target"])
        self.db.update("assessments", assessment_id, known_hosts=dumps(known) if known else None)
        audit.record(self.db, "assessment.known_hosts_set", actor, assessment_id, count=len(known))
        if gate(self.assessment(assessment_id), "discovery") is None:
            self.enqueue(assessment_id, "discovery", actor)
        return known

    def check_ownership(self, assessment_id, actor=None):
        a = self.assessment(assessment_id)
        if a["ownership_verified_at"]:
            return True, "Already verified."
        verified, method, message = ownership.check(self.net, a)
        self.db.update("assessments", assessment_id, ownership_last_check=now(), ownership_last_result=message)
        if verified:
            self.db.update("assessments", assessment_id, ownership_verified_at=now(), ownership_method=method,
                           ownership_verified_by=None, ownership_note=message)
            audit.record(self.db, "ownership.verified", actor, assessment_id, method=method, detail=message)
            self._ownership_done(assessment_id)
        elif actor:
            audit.record(self.db, "ownership.check", actor, assessment_id, result=message)
        return verified, message

    def record_manual_ownership(self, assessment_id, actor, note, file_path=None):
        if not note.strip():
            raise ValueError("Describe the proof (who confirmed ownership, how, and when).")
        self.db.update("assessments", assessment_id, ownership_verified_at=now(), ownership_method="manual",
                       ownership_verified_by=actor["id"], ownership_note=note.strip(), ownership_file=file_path)
        audit.record(self.db, "ownership.recorded_manually", actor, assessment_id, note=note.strip(),
                     file=Path(file_path).name if file_path else None)
        self._ownership_done(assessment_id)

    def _ownership_done(self, assessment_id):
        a = self.assessment(assessment_id)
        for module in AUTO_MODULES:
            self.enqueue(assessment_id, module, None)
        creator = self.user(a["created_by"])
        notify.send(self.db, self.config, "ownership_verified", [creator["email"]] if creator else [],
                    f"Ownership proven for {a['target']}",
                    f"Ownership of {a['target']} is proven ({a['ownership_method']}). "
                    "The automatic checks have started.", assessment_id)

    def recheck_pending_ownership(self):
        cutoff_recheck = timedelta(minutes=self.config.ownership_recheck_minutes)
        give_up = timedelta(days=self.config.ownership_give_up_days)
        current = parse_time(now())
        for a in self.db.all("SELECT * FROM assessments WHERE ownership_verified_at IS NULL"):
            if current - parse_time(a["created_at"]) > give_up:
                continue
            last = parse_time(a["ownership_last_check"])
            if last and current - last < cutoff_recheck:
                continue
            self.check_ownership(a["id"])

    def confirm_headsup(self, assessment_id, actor, note, scope):
        if not note.strip():
            raise ValueError("Say which providers were told and how (for example: emailed AWS abuse on 3 May).")
        if not scope:
            raise ValueError("The scan scope is empty; run Discovery first or enter the addresses.")
        self.db.update("assessments", assessment_id, headsup_at=now(), headsup_by=actor["id"],
                       headsup_note=note.strip(), headsup_scope=dumps(scope))
        audit.record(self.db, "services.headsup_confirmed", actor, assessment_id, note=note.strip(), scope=scope)
        self.enqueue(assessment_id, "services", actor)
        self.enqueue(assessment_id, "lifecycle", actor)

    def record_approval(self, assessment_id, actor, note, file_path=None):
        if not note.strip():
            raise ValueError("Describe the written approval (who approved, date, reference).")
        self.db.update("assessments", assessment_id, approval_at=now(), approval_by=actor["id"],
                       approval_note=note.strip(), approval_file=file_path)
        audit.record(self.db, "vulns.approval_recorded", actor, assessment_id, note=note.strip(),
                     file=Path(file_path).name if file_path else None)
        self._maybe_vulns(assessment_id, actor)

    def record_report(self, assessment_id, actor, file_path):
        digest = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
        self.db.update("assessments", assessment_id, report_file=str(file_path), report_sha256=digest,
                       report_at=now(), report_by=actor["id"])
        audit.record(self.db, "vulns.report_uploaded", actor, assessment_id, sha256=digest,
                     file=Path(file_path).name)
        self._maybe_vulns(assessment_id, actor)

    def _maybe_vulns(self, assessment_id, actor):
        if gate(self.assessment(assessment_id), "vulns") is None:
            self.enqueue(assessment_id, "vulns", actor)

    # Queue -------------------------------------------------------------------
    def enqueue(self, assessment_id, module, actor):
        a = self.assessment(assessment_id)
        if a["signed_off_at"]:
            raise GateClosed("This assessment is signed off and locked.")
        reason = gate(a, module)
        if reason:
            raise GateClosed(reason)
        pending = self.db.one("SELECT id FROM module_runs WHERE assessment_id = ? AND module = ? AND status = 'queued'",
                              (assessment_id, module))
        if pending:
            return pending["id"]
        run_id = self.db.run("INSERT INTO module_runs (assessment_id, module, status, triggered_by, queued_at)"
                             " VALUES (?, ?, 'queued', ?, ?)",
                             (assessment_id, module, actor["id"] if actor else None, now()))
        self.db.update("assessments", assessment_id, status="running")
        if actor:
            audit.record(self.db, "module.queued", actor, assessment_id, module=module)
        return run_id

    def next_run(self):
        rows = self.db.all("SELECT * FROM module_runs WHERE status = 'queued' ORDER BY id")
        if not rows:
            return None
        # Take the oldest assessment's work first, in module order.
        first = rows[0]["assessment_id"]
        same = [r for r in rows if r["assessment_id"] == first]
        running = self.db.one("SELECT id FROM module_runs WHERE assessment_id = ? AND status = 'running'", (first,))
        if running:
            return None
        same.sort(key=lambda r: ORDER.index(r["module"]))
        return same[0]

    def work_once(self):
        with self._lock:
            run = self.next_run()
            if not run:
                return False
            self.db.update("module_runs", run["id"], status="running", started_at=now())
        self.execute(run)
        return True

    def work_until_idle(self, limit=100):
        for _ in range(limit):
            if not self.work_once():
                return

    def recover(self):
        """Runs left 'running' by a restart are marked failed and queued again."""
        for run in self.db.all("SELECT * FROM module_runs WHERE status = 'running'"):
            self.db.update("module_runs", run["id"], status="error", finished_at=now(),
                           error="Interrupted by a restart; queued again.")
            self.db.run("INSERT INTO module_runs (assessment_id, module, status, triggered_by, queued_at)"
                        " VALUES (?, ?, 'queued', ?, ?)", (run["assessment_id"], run["module"], None, now()))

    def execute(self, run):
        a = self.assessment(run["assessment_id"])
        a["headsup_scope_list"] = loads(a.get("headsup_scope"), [])
        a["known_hosts_list"] = loads(a.get("known_hosts"), [])
        reason = gate(a, run["module"])
        if reason or a["signed_off_at"]:
            self.db.update("module_runs", run["id"], status="skipped", finished_at=now(),
                           error=reason or "Signed off.")
            self._after_run(a["id"])
            return
        ctx = Context(assessment=a, net=self.net, config=self.config,
                      prior=self.prior_evidence(a["id"]), report_path=a.get("report_file") or "")
        state = {"abandoned": False}

        def progress(message):
            if state["abandoned"]:
                return
            log(f"[{a['target']} #{run['id']} {run['module']}] {message}")
            self.db.update("module_runs", run["id"], progress=message[:300])

        ctx.on_progress = progress
        started = now()
        clock = time.monotonic()
        log(f"[{a['target']} #{run['id']} {run['module']}] started")
        try:
            if run["module"] in DNS_MODULES and a["target_type"] == "domain" and self.net.nxdomain(a["target"]) is not False:
                # Without this, a broken resolver would read as "no SPF", "no DMARC" and so on.
                message = ("The domain does not resolve from this server (DNS unreachable, or the domain is not "
                           "registered). Nothing was judged; re-run once DNS works.")
                ctx.evidence["dns_unavailable"] = True
                results = [{"control_id": c.id, "status": "inconclusive", "summary": message, "details": {},
                            "review": True} for c in for_module(run["module"])]
            else:
                results = self._run_with_time_limit(run, ctx, state)
            error = None
        except Exception as exc:  # a module bug or a hang must not stop the worker
            error = f"{exc.__class__.__name__}: {exc}"
            ctx.evidence["traceback"] = traceback.format_exc()
            results = [{"control_id": c.id, "status": "inconclusive", "summary": f"Module failed: {error}",
                        "details": {}, "review": True} for c in for_module(run["module"])]
        returned = {r["control_id"] for r in results}
        for c in for_module(run["module"]):
            if c.id not in returned:
                results.append({"control_id": c.id, "status": "inconclusive", "summary": "Module returned no result.",
                                "details": {}, "review": True})
        try:
            evidence = dict(ctx.evidence)  # an abandoned module thread may still be writing to it
        except RuntimeError:
            evidence = {}
        evidence_path, digest = self._write_evidence(a, run, started, evidence, results)
        self._store_results(a["id"], run, results)
        self.db.update("module_runs", run["id"], status="error" if error else "done", finished_at=now(),
                       evidence_path=str(evidence_path), evidence_sha256=digest, error=error,
                       progress=None)
        log(f"[{a['target']} #{run['id']} {run['module']}] {'FAILED: ' + error if error else 'done'}"
            f" after {round(time.monotonic() - clock)}s")
        audit.record(self.db, "module.finished", None, a["id"], module=run["module"],
                     status="error" if error else "done", evidence_sha256=digest)
        if error:
            creator = self.user(a["created_by"])
            notify.send(self.db, self.config, "module_failed", [creator["email"]] if creator else [],
                        f"{MODULES[run['module']]} check failed for {a['target']}",
                        f"The {MODULES[run['module']]} module failed: {error}. Its controls are marked "
                        "Inconclusive and flagged for review. You can re-run it from the assessment page.", a["id"])
        if run["module"] in ("web", "services") and gate(a, "lifecycle") is None:
            self.enqueue(a["id"], "lifecycle", None)
        self._after_run(a["id"])

    def _run_with_time_limit(self, run, ctx, state):
        """Runs the module in its own thread. If it overruns, the worker stops waiting and moves on;
        the stuck thread is left to finish (or not) on its own."""
        box = {}

        def target():
            try:
                box["results"] = get_runner(run["module"])(ctx)
            except Exception as exc:
                box["error"] = exc
                box["traceback"] = traceback.format_exc()

        minutes = MODULE_TIMEOUT_MINUTES.get(run["module"], 15)
        thread = threading.Thread(target=target, name=f"module-{run['module']}-{run['id']}", daemon=True)
        thread.start()
        thread.join(minutes * 60)
        if thread.is_alive():
            state["abandoned"] = True
            last = self.db.one("SELECT progress FROM module_runs WHERE id = ?", (run["id"],))["progress"]
            raise ModuleTimeout(f"no result after {minutes} minutes (last step: {last or 'none'}). "
                                "A network service did not answer; re-run later.")
        if "error" in box:
            ctx.evidence["traceback"] = box["traceback"]
            raise box["error"]
        return box["results"]

    def _write_evidence(self, a, run, started, data, results):
        folder = Path(self.config.evidence_dir) / str(a["id"])
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{run['id']:05d}-{run['module']}.json"
        payload = {"assessment_id": a["id"], "target": a["target"], "module": run["module"], "run_id": run["id"],
                   "started_at": started, "finished_at": now(), "demo": self.config.demo,
                   "data": data, "results": results}
        raw = json.dumps(payload, indent=2, sort_keys=True, default=str).encode()
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def _store_results(self, assessment_id, run, results):
        stamp = now()
        with self.db.connect() as conn:
            for r in results:
                conn.execute(
                    "INSERT INTO results (assessment_id, control_id, module, status, original_status, summary, details,"
                    " needs_review, module_run_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (assessment_id, control_id) DO UPDATE SET status = excluded.status,"
                    " original_status = excluded.original_status, summary = excluded.summary,"
                    " details = excluded.details, needs_review = excluded.needs_review,"
                    " module_run_id = excluded.module_run_id, updated_at = excluded.updated_at,"
                    " reviewed_by = NULL, reviewed_at = NULL, review_note = NULL",
                    (assessment_id, r["control_id"], BY_ID[r["control_id"]].module, r["status"], r["status"],
                     r["summary"], dumps(r.get("details") or {}), 1 if r.get("review") else 0, run["id"], stamp))

    def _after_run(self, assessment_id):
        busy = self.db.one("SELECT COUNT(*) AS n FROM module_runs WHERE assessment_id = ?"
                           " AND status IN ('queued', 'running')", (assessment_id,))["n"]
        a = self.assessment(assessment_id)
        if busy or a["signed_off_at"]:
            return
        self.db.update("assessments", assessment_id, status="in_review", review_notified_at=now())
        flagged = sum(1 for r in self.results(assessment_id) if r["needs_review"] and not r["reviewed_at"])
        reviewers = [u["email"] for u in self.users_with_role("reviewer")]
        waiting = [s["label"] for m, s in self.module_states(a).items() if s["gate"] and not s["latest"]]
        body = (f"Checks for {a['target']} have finished and are waiting for review. "
                f"{flagged} result(s) are flagged for a human decision.")
        if waiting:
            body += " Still waiting on approvals for: " + ", ".join(waiting) + "."
        notify.send(self.db, self.config, "ready_for_review", reviewers,
                    f"Ready for review: {a['target']}", body, assessment_id)

    # Review and sign-off -----------------------------------------------------
    def review_result(self, assessment_id, control_id, actor, new_status, note):
        a = self.assessment(assessment_id)
        if a["signed_off_at"]:
            raise ValueError("This assessment is signed off and locked.")
        row = self.db.one("SELECT * FROM results WHERE assessment_id = ? AND control_id = ?", (assessment_id, control_id))
        if not row:
            raise ValueError("That control has no result yet.")
        note = (note or "").strip()
        changed = new_status != row["status"]
        if changed and not note:
            raise ValueError("A written note is required to change a result.")
        if row["status"] in ("review", "inconclusive") and new_status == row["status"]:
            raise ValueError("Choose a final result (Pass, Partial, Fail, Not applicable or Information).")
        self.db.update("results", row["id"], status=new_status, reviewed_by=actor["id"], reviewed_at=now(),
                       review_note=note or None, needs_review=0, updated_at=now())
        audit.record(self.db, "result.changed" if changed else "result.confirmed", actor, assessment_id,
                     control=control_id, before=row["status"], after=new_status, note=note or None)

    def signoff_check(self, assessment_id, actor):
        """Returns (allowed, self_signoff, reason)."""
        a = self.assessment(assessment_id)
        if "reviewer" not in actor["roles"].split(","):
            return False, False, "Only a reviewer can sign off."
        if a["signed_off_at"]:
            return False, False, "Already signed off."
        if a["status"] != "in_review":
            return False, False, "Checks are still running or have not started."
        open_flags = [r["control_id"] for r in self.results(assessment_id) if r["needs_review"] and not r["reviewed_at"]]
        if open_flags:
            return False, False, f"{len(open_flags)} flagged result(s) still need a decision: " + ", ".join(open_flags[:8])
        involved = actor["id"] in self.involvement(a)
        others = [u for u in self.users_with_role("reviewer") if u["id"] != actor["id"]]
        if involved and others:
            return False, False, ("You ran or approved part of this assessment. Another reviewer must sign it off: "
                                  + ", ".join(u["name"] for u in others[:3]) + ".")
        return True, involved, ""

    def sign_off(self, assessment_id, actor, note):
        allowed, self_signoff, reason = self.signoff_check(assessment_id, actor)
        if not allowed:
            raise ValueError(reason)
        score = self.score(assessment_id)
        self.db.update("assessments", assessment_id, status="signed_off", signed_off_at=now(),
                       signed_off_by=actor["id"], signoff_note=(note or "").strip() or None,
                       self_signoff=1 if self_signoff else 0, score_json=dumps(score))
        audit.record(self.db, "assessment.signed_off", actor, assessment_id, score=score["score"], grade=score["grade"],
                     self_signoff=self_signoff,
                     reason="only reviewer on the team" if self_signoff else None)
        a = self.assessment(assessment_id)
        client = self.db.one("SELECT * FROM clients WHERE id = ?", (a["client_id"],))
        recipients = [u["email"] for u in self.db.all("SELECT * FROM users WHERE client_id = ? AND active = 1",
                                                      (a["client_id"],))]
        if client and client["contact_email"]:
            recipients.append(client["contact_email"])
        creator = self.user(a["created_by"])
        if creator:
            recipients.append(creator["email"])
        grade = f"{score['score']} ({score['grade']})" if score["score"] is not None else "not scored"
        notify.send(self.db, self.config, "signed_off", recipients, f"CyberHealth report ready: {a['target']}",
                    f"The External CyberHealth Check for {a['target']} has been reviewed and signed off. "
                    f"CyberHealth Score v{scoring.VERSION}: {grade}.", assessment_id)


class Worker(threading.Thread):
    daemon = True

    def __init__(self, service, idle_seconds=2.0, ownership_every=60.0):
        super().__init__(name="cyberhealth-worker")
        self.service = service
        self.idle_seconds = idle_seconds
        self.ownership_every = ownership_every
        self.stopping = threading.Event()

    def run(self):
        self.service.recover()
        last_ownership = 0.0
        while not self.stopping.is_set():
            try:
                if time.monotonic() - last_ownership > self.ownership_every:
                    last_ownership = time.monotonic()
                    self.service.recheck_pending_ownership()
                if self.service.work_once():
                    continue
            except Exception:  # keep the worker alive; the error is in the logs
                traceback.print_exc()
            self.stopping.wait(self.idle_seconds)
