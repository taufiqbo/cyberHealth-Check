"""Settings, read once from the environment (see .env.example)."""
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Config:
    demo: bool = False
    data_dir: Path = Path("./data")
    host: str = "localhost"
    secret_key: str = ""
    admin_email: str = ""
    admin_password: str = ""
    admin_name: str = "Administrator"
    scan_ip: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    webhook_url: str = ""
    nvd_api_key: str = ""
    max_web_hosts: int = 10
    max_scan_hosts: int = 16
    ownership_recheck_minutes: int = 10
    ownership_give_up_days: int = 14
    inline_worker: bool = True
    secure_cookies: bool = False
    tool_paths: dict = field(default_factory=dict)
    lookalike_tlds: list = field(default_factory=lambda: ["com", "net", "org", "my", "com.my"])
    brand_name: str = "BINTARA"
    brand_tagline: str = "We get IT Done. Delivered"
    brand_contact: str = ""
    brand_legal: str = "Bintara Solutions Sdn Bhd"

    @property
    def db_path(self):
        return self.data_dir / "runner.db"

    @property
    def evidence_dir(self):
        return self.data_dir / "evidence"

    @property
    def uploads_dir(self):
        return self.data_dir / "uploads"

    @property
    def branding_dir(self):
        return self.data_dir / "branding"

    @property
    def cache_dir(self):
        return self.data_dir / "cache"


def load_config(**overrides):
    demo = _bool("RUNNER_DEMO")
    data_dir = Path(os.environ.get("RUNNER_DATA_DIR", "./demo-data" if demo else "./data"))
    secret = os.environ.get("RUNNER_SECRET_KEY", "")
    if not secret:
        # A random key still works; sessions just end when the process restarts.
        secret = secrets.token_hex(32)
    cfg = Config(
        demo=demo,
        data_dir=data_dir,
        host=os.environ.get("RUNNER_HOST", "localhost"),
        secret_key=secret,
        admin_email=os.environ.get("RUNNER_ADMIN_EMAIL", "").strip().lower(),
        admin_password=os.environ.get("RUNNER_ADMIN_PASSWORD", ""),
        admin_name=os.environ.get("RUNNER_ADMIN_NAME", "Administrator"),
        scan_ip=os.environ.get("RUNNER_SCAN_IP", ""),
        smtp_host=os.environ.get("SMTP_HOST", ""),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.environ.get("SMTP_USER", ""),
        smtp_password=os.environ.get("SMTP_PASSWORD", ""),
        smtp_from=os.environ.get("SMTP_FROM", ""),
        smtp_starttls=_bool("SMTP_STARTTLS", True),
        webhook_url=os.environ.get("NOTIFY_WEBHOOK_URL", ""),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        max_web_hosts=_int("RUNNER_MAX_WEB_HOSTS", 10),
        max_scan_hosts=_int("RUNNER_MAX_SCAN_HOSTS", 16),
        ownership_recheck_minutes=_int("RUNNER_OWNERSHIP_RECHECK_MINUTES", 10),
        ownership_give_up_days=_int("RUNNER_OWNERSHIP_GIVE_UP_DAYS", 14),
        inline_worker=_bool("RUNNER_INLINE_WORKER", True),
        secure_cookies=_bool("RUNNER_SECURE_COOKIES", not demo),
        brand_name=os.environ.get("RUNNER_BRAND_NAME", "BINTARA"),
        brand_tagline=os.environ.get("RUNNER_BRAND_TAGLINE", "We get IT Done. Delivered"),
        brand_contact=os.environ.get("RUNNER_BRAND_CONTACT", ""),
        brand_legal=os.environ.get("RUNNER_BRAND_LEGAL", "Bintara Solutions Sdn Bhd"),
        lookalike_tlds=[t for t in os.environ.get("RUNNER_LOOKALIKE_TLDS", "com,net,org,my,com.my").split(",") if t.strip()],
        tool_paths={
            "nmap": os.environ.get("NMAP_PATH", "nmap"),
            "dnstwist": os.environ.get("DNSTWIST_PATH", "dnstwist"),
            "amass": os.environ.get("AMASS_PATH", "amass"),
            "subfinder": os.environ.get("SUBFINDER_PATH", "subfinder"),
        },
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    for d in (cfg.data_dir, cfg.evidence_dir, cfg.uploads_dir, cfg.cache_dir, cfg.branding_dir):
        Path(d).mkdir(parents=True, exist_ok=True)
    return cfg
