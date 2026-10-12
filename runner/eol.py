"""End-of-life data: a bundled snapshot, refreshed from endoflife.date when reachable."""
import json
import re
import time
from datetime import date
from pathlib import Path

from .net import NetError

SNAPSHOT = Path(__file__).parent / "data" / "eol.json"
LIVE_PRODUCTS = ["php", "nginx", "apache-http-server", "openssl", "mysql", "postgresql", "tomcat"]
CACHE_SECONDS = 7 * 24 * 3600

# Banner / Nmap product text -> (product key, version regex)
PATTERNS = [
    ("php", re.compile(r"\bPHP/(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("nginx", re.compile(r"\bnginx/(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("apache-http-server", re.compile(r"\bApache/(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("openssl", re.compile(r"\bOpenSSL/(\d+\.\d+\.\d+)", re.I)),
    ("iis", re.compile(r"\bMicrosoft-IIS/(\d+\.\d+)", re.I)),
]
NMAP_PRODUCTS = {
    "nginx": "nginx", "apache httpd": "apache-http-server", "microsoft iis httpd": "iis",
    "mysql": "mysql", "postgresql db": "postgresql", "apache tomcat": "tomcat", "php": "php",
}
LABELS = {"php": "PHP", "nginx": "nginx", "apache-http-server": "Apache httpd", "openssl": "OpenSSL",
          "iis": "Microsoft IIS", "mysql": "MySQL", "postgresql": "PostgreSQL", "tomcat": "Apache Tomcat"}


def load(net=None, cache_dir=None):
    data = {k: v for k, v in json.loads(SNAPSHOT.read_text()).items() if not k.startswith("_")}
    source = "bundled snapshot"
    if net is None or getattr(net, "demo", False) or cache_dir is None:
        return data, source
    cache = Path(cache_dir) / "eol-live.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < CACHE_SECONDS:
        data.update(json.loads(cache.read_text()))
        return data, "endoflife.date (cached)"
    live = {}
    for product in LIVE_PRODUCTS:
        try:
            rows = net.get_json(f"https://endoflife.date/api/{product}.json", timeout=15)
        except NetError:
            continue
        live[product] = {str(r["cycle"]): r.get("eol", False) for r in rows if "cycle" in r}
    if live:
        cache.write_text(json.dumps(live))
        data.update(live)
        source = "endoflife.date"
    return data, source


def find_cycle(cycles, version):
    """Longest cycle that is a dotted prefix of version ('7.4' matches '7.4.3', '14' matches '14.5')."""
    best = None
    for cycle in cycles:
        if version == cycle or version.startswith(cycle + "."):
            if best is None or len(cycle) > len(best):
                best = cycle
    return best


def judge(product, version, data, today=None):
    """Returns dict with status: eol | soon | supported | unknown."""
    today = today or date.today()
    cycles = data.get(product, {})
    cycle = find_cycle(cycles, version)
    out = {"product": LABELS.get(product, product), "version": version, "cycle": cycle, "eol": None}
    if cycle is None:
        out["status"] = "unknown"
        return out
    eol = cycles[cycle]
    if eol is True:
        out["status"] = "eol"
        return out
    if not eol:
        out["status"] = "supported"
        return out
    eol_date = date.fromisoformat(eol)
    out["eol"] = eol
    days = (eol_date - today).days
    out["status"] = "eol" if days < 0 else "soon" if days <= 183 else "supported"
    return out


def from_banner(text):
    found = []
    for product, pattern in PATTERNS:
        for m in pattern.finditer(text or ""):
            found.append((product, m.group(1)))
    return found


def from_nmap(product, version):
    key = NMAP_PRODUCTS.get((product or "").strip().lower())
    m = re.match(r"(\d+(?:\.\d+){0,2})", version or "")
    if key and m:
        return key, m.group(1)
    return None
