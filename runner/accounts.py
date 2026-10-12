"""People, roles and sign-in."""
from datetime import timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import now, parse_time

STAFF_ROLES = ["admin", "analyst", "reviewer"]
ALL_ROLES = STAFF_ROLES + ["client"]
MAX_FAILURES = 5
LOCK_MINUTES = 15
MIN_PASSWORD = 10


def roles_of(user):
    return set(user["roles"].split(",")) if user else set()


def validate_roles(roles):
    roles = [r for r in roles if r in ALL_ROLES]
    if not roles:
        raise ValueError("Choose at least one role.")
    if "client" in roles and len(roles) > 1:
        raise ValueError("A client account cannot also hold staff roles.")
    return roles


def create_user(db, email, name, password, roles, client_id=None, actor=None, check_strength=True):
    email = (email or "").strip().lower()
    if "@" not in email:
        raise ValueError("Enter a valid email address.")
    if check_strength and len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Passwords need at least {MIN_PASSWORD} characters.")
    roles = validate_roles(roles)
    if "client" in roles and not client_id:
        raise ValueError("A client account must belong to a client.")
    if db.one("SELECT id FROM users WHERE email = ?", (email,)):
        raise ValueError("Someone already uses that email address.")
    uid = db.run("INSERT INTO users (email, name, password_hash, roles, client_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                 (email, name.strip() or email, generate_password_hash(password), ",".join(roles),
                  client_id if "client" in roles else None, now()))
    audit.record(db, "user.created", actor, None, user=email, roles=roles, client_id=client_id)
    return uid


def authenticate(db, email, password):
    """Returns (user, error)."""
    email = (email or "").strip().lower()
    user = db.one("SELECT * FROM users WHERE email = ?", (email,))
    if not user or not user["active"]:
        audit.record(db, "login.failed", None, None, email=email, reason="unknown or inactive")
        return None, "Wrong email or password."
    locked = parse_time(user["locked_until"])
    if locked and locked > parse_time(now()):
        return None, "Too many failed attempts. Try again in a few minutes."
    if not check_password_hash(user["password_hash"], password or ""):
        failures = user["failed_logins"] + 1
        lock = None
        if failures >= MAX_FAILURES:
            lock = (parse_time(now()) + timedelta(minutes=LOCK_MINUTES)).isoformat()
            failures = 0
        db.update("users", user["id"], failed_logins=failures, locked_until=lock)
        audit.record(db, "login.failed", None, None, email=email, reason="wrong password", locked=bool(lock))
        return None, "Wrong email or password."
    db.update("users", user["id"], failed_logins=0, locked_until=None)
    audit.record(db, "login", user)
    return user, None


def set_password(db, user_id, password, actor):
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Passwords need at least {MIN_PASSWORD} characters.")
    db.update("users", user_id, password_hash=generate_password_hash(password), failed_logins=0, locked_until=None)
    target = db.one("SELECT email FROM users WHERE id = ?", (user_id,))
    audit.record(db, "user.password_changed", actor, None, user=target["email"])


def bootstrap_admin(db, config):
    """The first account holds all three staff roles so a one-person team can work."""
    if db.one("SELECT id FROM users LIMIT 1"):
        return None
    if not config.admin_email or not config.admin_password:
        raise SystemExit("Set RUNNER_ADMIN_EMAIL and RUNNER_ADMIN_PASSWORD for the first start (see .env.example).")
    return create_user(db, config.admin_email, config.admin_name, config.admin_password, STAFF_ROLES)
