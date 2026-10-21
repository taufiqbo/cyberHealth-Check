"""Logos and brand names: one platform default, optionally overridden per organization (white label)."""
import uuid
from io import BytesIO
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from . import audit

MAX_BYTES = 2 * 1024 * 1024
MIN_PX, MAX_PX = 16, 2048


def _setting(db, key):
    row = db.one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] if row else None


def _set(db, key, value):
    db.run("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
           (key, value))


def clean_logo(raw):
    """Checks a PNG/JPEG upload and re-encodes it as PNG, which drops anything that is not pixels."""
    if len(raw) > MAX_BYTES:
        raise ValueError("The logo must be 2 MB or smaller.")
    try:
        img = Image.open(BytesIO(raw))
        fmt = img.format
        img.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("That file is not a readable PNG or JPEG image.") from exc
    if fmt not in ("PNG", "JPEG"):
        raise ValueError("Upload a PNG or JPEG file.")
    w, h = img.size
    if not (MIN_PX <= w <= MAX_PX and MIN_PX <= h <= MAX_PX):
        raise ValueError(f"The logo must be between {MIN_PX} and {MAX_PX} pixels wide and high (this one is {w}×{h}).")
    img = img.convert("RGBA")
    out = BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


def platform(db, config):
    name = _setting(db, "brand_name") or config.brand_name
    logo = _setting(db, "logo_file")
    return {"name": name, "logo": logo if logo and (Path(config.branding_dir) / logo).exists() else None}


def for_client(db, config, client):
    """The brand an organization's users and reports see: its own if set, else the platform's."""
    base = platform(db, config)
    if not client:
        return {**base, "scope": "platform"}
    logo = client.get("logo_file")
    has_logo = bool(logo and (Path(config.branding_dir) / logo).exists())
    return {"name": client.get("brand_name") or base["name"],
            "logo": logo if has_logo else base["logo"],
            "scope": f"org-{client['id']}" if has_logo else "platform",
            "custom": bool(client.get("brand_name") or has_logo)}


def logo_path(config, filename):
    return Path(config.branding_dir) / filename if filename else None


def save(db, config, actor, client_id, name, raw_logo, restore):
    """client_id None means the platform default."""
    name = (name or "").strip()[:60]
    new_file = None
    if raw_logo:
        data = clean_logo(raw_logo)
        new_file = f"{'platform' if client_id is None else f'org-{client_id}'}-{uuid.uuid4().hex[:10]}.png"
        (Path(config.branding_dir) / new_file).write_bytes(data)
    if client_id is None:
        old = _setting(db, "logo_file")
        _set(db, "brand_name", name or None)
        if restore:
            _set(db, "logo_file", None)
        elif new_file:
            _set(db, "logo_file", new_file)
    else:
        client = db.one("SELECT * FROM clients WHERE id = ?", (client_id,))
        if not client:
            raise ValueError("Choose an organization.")
        old = client["logo_file"]
        logo = None if restore else (new_file or old)
        db.update("clients", client_id, brand_name=name or None, logo_file=logo)
    if (restore or new_file) and old and old != new_file:
        stale = Path(config.branding_dir) / old
        if stale.exists():
            stale.unlink()
    audit.record(db, "branding.updated", actor, None, scope="platform" if client_id is None else f"client {client_id}",
                 brand_name=name or None, logo="restored to default" if restore else ("uploaded" if new_file else "unchanged"))
