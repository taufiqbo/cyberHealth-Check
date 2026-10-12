"""Append-only audit trail. Each row carries the hash of the row before it,
so an edit or deletion in the database shows up when the chain is verified."""
import hashlib

from .db import _audit_lock, dumps, now

GENESIS = "0" * 64


def _digest(prev_hash, at, actor_id, actor, action, assessment_id, detail):
    payload = dumps([prev_hash, at, actor_id, actor, action, assessment_id, detail])
    return hashlib.sha256(payload.encode()).hexdigest()


def record(db, action, actor=None, assessment_id=None, **detail):
    """actor is a user dict, or None for the system itself."""
    actor_id = actor["id"] if actor else None
    actor_label = actor["email"] if actor else "system"
    detail_json = dumps(detail) if detail else None
    with _audit_lock, db.connect() as conn:
        last = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["hash"] if last else GENESIS
        at = now()
        digest = _digest(prev_hash, at, actor_id, actor_label, action, assessment_id, detail_json)
        conn.execute(
            "INSERT INTO audit (at, actor_id, actor, action, assessment_id, detail, prev_hash, hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (at, actor_id, actor_label, action, assessment_id, detail_json, prev_hash, digest),
        )


def verify_chain(db):
    """Returns (ok, first_bad_id)."""
    prev_hash = GENESIS
    for row in db.all("SELECT * FROM audit ORDER BY id"):
        expected = _digest(prev_hash, row["at"], row["actor_id"], row["actor"], row["action"],
                           row["assessment_id"], row["detail"])
        if row["prev_hash"] != prev_hash or row["hash"] != expected:
            return False, row["id"]
        prev_hash = row["hash"]
    return True, None
