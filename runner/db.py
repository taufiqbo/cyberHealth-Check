"""SQLite storage. One connection per call keeps the web threads and the worker apart."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    contact_email TEXT,
    created_at TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'complimentary',
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL,
    client_id INTEGER REFERENCES clients(id),
    active INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id),
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    ownership_token TEXT NOT NULL,
    ownership_method TEXT,
    ownership_verified_at TEXT,
    ownership_verified_by INTEGER,
    ownership_note TEXT,
    ownership_file TEXT,
    ownership_last_check TEXT,
    ownership_last_result TEXT,
    scan_scope TEXT,
    headsup_at TEXT,
    headsup_by INTEGER,
    headsup_note TEXT,
    headsup_scope TEXT,
    approval_at TEXT,
    approval_by INTEGER,
    approval_note TEXT,
    approval_file TEXT,
    report_file TEXT,
    report_sha256 TEXT,
    report_at TEXT,
    report_by INTEGER,
    review_notified_at TEXT,
    signed_off_at TEXT,
    signed_off_by INTEGER,
    signoff_note TEXT,
    self_signoff INTEGER NOT NULL DEFAULT 0,
    score_json TEXT,
    known_hosts TEXT,
    summary_text TEXT
);
CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id),
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    triggered_by INTEGER,
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    evidence_path TEXT,
    evidence_sha256 TEXT,
    error TEXT,
    progress TEXT
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id),
    control_id TEXT NOT NULL,
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    original_status TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT,
    needs_review INTEGER NOT NULL DEFAULT 0,
    module_run_id INTEGER REFERENCES module_runs(id),
    reviewed_by INTEGER,
    reviewed_at TEXT,
    review_note TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE (assessment_id, control_id)
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    assessment_id INTEGER,
    recipient TEXT NOT NULL,
    channel TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    delivery TEXT NOT NULL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    actor_id INTEGER,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    assessment_id INTEGER,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_status ON module_runs(status);
CREATE INDEX IF NOT EXISTS idx_results_assessment ON results(assessment_id);
"""

_audit_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value)


class Database:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            # Databases made by older versions lack newer columns.
            for table, column, kind in (("module_runs", "progress", "TEXT"), ("assessments", "known_hosts", "TEXT"),
                                        ("assessments", "summary_text", "TEXT"),
                                        ("clients", "tier", "TEXT NOT NULL DEFAULT 'complimentary'"),
                                        ("clients", "active", "INTEGER NOT NULL DEFAULT 1")):
                columns = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if column not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def all(self, sql, params=()):
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        with self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def run(self, sql, params=()):
        with self.connect() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid

    def update(self, table, row_id, **fields):
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.run(f"UPDATE {table} SET {cols} WHERE id = ?", (*fields.values(), row_id))


def dumps(value):
    return json.dumps(value, sort_keys=True, default=str)


def loads(value, default=None):
    if not value:
        return default
    return json.loads(value)
