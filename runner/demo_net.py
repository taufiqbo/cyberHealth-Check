"""Demo mode: a fictional client (client-example.com) answered from fixtures. Nothing leaves the machine."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .net import HttpResponse, NetError, TlsInfo

DOMAIN = "client-example.com"
DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"

A = {
    DOMAIN: ["192.0.2.10"],
    f"www.{DOMAIN}": ["192.0.2.10"],
    f"mail.{DOMAIN}": ["192.0.2.20"],
    f"dev.{DOMAIN}": ["192.0.2.30"],
    f"vpn.{DOMAIN}": ["192.0.2.40"],
    "ns1.dns-host.example": ["198.51.100.53"],
    "ns2.dns-host.example": ["198.51.100.54"],
    "client-exampie.com": ["203.0.113.66"],
    "cliente-xample.com": ["203.0.113.67"],
}
CNAME = {f"old.{DOMAIN}": ["clientexample-old.azurewebsites.net"]}
TXT = {
    DOMAIN: ["v=spf1 mx include:_spf.mailhost.example ~all", "google-site-verification=demo"],
    "_spf.mailhost.example": ["v=spf1 ip4:198.51.100.0/24 -all"],
    f"_dmarc.{DOMAIN}": ["v=DMARC1; p=none; rua=mailto:dmarc@client-example.com"],
    f"selector1._domainkey.{DOMAIN}": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdemo"],
}
MX = {DOMAIN: [f"mail.{DOMAIN}"], "client-exampie.com": ["mx.client-exampie.com"]}
NS = {DOMAIN: ["ns1.dns-host.example", "ns2.dns-host.example"]}
CT_NAMES = [DOMAIN, f"www.{DOMAIN}", f"mail.{DOMAIN}", f"dev.{DOMAIN}", f"old.{DOMAIN}", f"vpn.{DOMAIN}",
            f"*.{DOMAIN}"]

SECURITY_HEADERS = [
    ("Server", "Apache/2.4.41 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.4.3"),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("X-Content-Type-Options", "nosniff"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Type", "text/html; charset=UTF-8"),
]
HOME = "<html><head><title>Client Example Ltd | Home</title></head><body><h1>Welcome</h1></body></html>"


def _cert(host, days_left, sans=None, self_signed=False):
    now = datetime.now(timezone.utc)
    return {"subject_cn": host, "sans": sans or [host], "issuer": "Demo CA" if not self_signed else host,
            "not_after": (now + timedelta(days=days_left)).isoformat(),
            "not_before": (now - timedelta(days=90 - days_left)).isoformat(), "self_signed": self_signed}


class DemoNet:
    demo = True

    def __init__(self, token_lookup=None):
        self.token_lookup = token_lookup or (lambda domain: [])

    # DNS
    def resolve(self, name, rtype):
        name = name.lower().rstrip(".")
        if rtype == "TXT" and name == f"_cyberhealth.{DOMAIN}":
            # The fictional client has published the token for every assessment of its domain.
            return [f"cyberhealth-verify={t}" for t in self.token_lookup(DOMAIN)]
        table = {"A": A, "CNAME": CNAME, "TXT": TXT, "MX": MX, "NS": NS}.get(rtype, {})
        return list(table.get(name, []))

    def nxdomain(self, name):
        name = name.lower().rstrip(".")
        return not any(name in t for t in (A, CNAME, TXT, MX, NS))

    def axfr_allowed(self, domain, nameserver):
        return False

    # HTTP
    def http(self, method, url, timeout=10, max_body=200_000):
        if url == f"http://{DOMAIN}/" or url == f"http://www.{DOMAIN}/":
            return HttpResponse(301, [("Location", url.replace("http://", "https://"))], "", url)
        if url == f"https://{DOMAIN}/":
            return HttpResponse(301, [("Location", f"https://www.{DOMAIN}/"),
                                      ("Strict-Transport-Security", "max-age=31536000")], "", url)
        if url == f"https://www.{DOMAIN}/":
            headers = SECURITY_HEADERS + [("Set-Cookie", "PHPSESSID=demo123; path=/; HttpOnly")]
            return HttpResponse(200, headers, "" if method == "HEAD" else HOME, url)
        if url.startswith(f"https://{DOMAIN}/") or url.startswith(f"http://{DOMAIN}/"):
            return HttpResponse(404, [("Content-Type", "text/html")], "<h1>Not Found</h1>", url)
        raise NetError(f"{method} {url}: ConnectionError (demo: host not in fixture)")

    def get_json(self, url, headers=None, timeout=30):
        if "known_exploited_vulnerabilities" in url:
            return json.loads((DEMO_DIR / "kev-sample.json").read_text())
        if "nvd.nist.gov" in url:
            cve = url.rsplit("=", 1)[1]
            published = json.loads((DEMO_DIR / "nvd-sample.json").read_text()).get(cve)
            return {"vulnerabilities": [{"cve": {"id": cve, "published": published}}] if published else []}
        raise NetError(f"GET {url}: demo mode has no network")

    # TLS
    def tls_handshake(self, host, port=443, timeout=8):
        if host in (DOMAIN, f"www.{DOMAIN}"):
            return TlsInfo(ok=True, verified=True, hostname_ok=True, version="TLSv1.3",
                           cipher="TLS_AES_256_GCM_SHA384", cert=_cert(host, 64, [DOMAIN, f"www.{DOMAIN}"]))
        if host == f"mail.{DOMAIN}":
            return TlsInfo(ok=True, verified=True, hostname_ok=True, version="TLSv1.2",
                           cipher="ECDHE-RSA-AES128-GCM-SHA256", cert=_cert(host, 20))
        if host == f"dev.{DOMAIN}":
            return TlsInfo(ok=True, verified=False, hostname_ok=True, verify_error="self-signed certificate",
                           version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256",
                           cert=_cert(host, 300, self_signed=True))
        if host == f"vpn.{DOMAIN}":
            return TlsInfo(ok=True, verified=True, hostname_ok=True, version="TLSv1.2",
                           cipher="ECDHE-RSA-AES256-SHA384", cert=_cert(host, 120))
        return TlsInfo(ok=False, error="ConnectionRefusedError (demo: host not in fixture)")

    def tls_accepts(self, host, probe, port=443, timeout=8):
        if probe in ("RC4", "3DES"):
            return None  # like a real OpenSSL 3 build: these cannot be offered at all
        if host == f"vpn.{DOMAIN}" and probe == "TLSv1.1":
            return True
        return False

    def ct_names(self, domain):
        if domain == DOMAIN:
            return list(CT_NAMES), "crt.sh (demo fixture)"
        raise NetError("demo mode has no network")

    def rdap(self, domain):
        if domain != DOMAIN:
            raise NetError("demo mode has no network")
        expires = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"events": [{"eventAction": "expiration", "eventDate": expires}],
                "status": ["client transfer prohibited", "active"]}

    # Tools
    def which(self, tool):
        return {"nmap": "nmap", "dnstwist": "dnstwist"}.get(tool)

    def tool_argv(self, tool):
        path = self.which(tool)
        return [path] if path else None

    def whois(self, domain, timeout=20):
        raise NetError("demo mode has no network")

    def run(self, argv, timeout=1800):
        tool = argv[0]
        if tool == "dnstwist":
            target = argv[-1]
            if target != DOMAIN:
                return 0, json.dumps([{"fuzzer": "*original", "domain": target}]), ""
            return 0, (DEMO_DIR / "dnstwist-sample.json").read_text(), ""
        if tool == "nmap":
            name = "nmap-pass2.xml" if "-sV" in argv else "nmap-pass1.xml"
            return 0, (DEMO_DIR / name).read_text(), ""
        raise NetError(f"{tool}: not available in demo mode")
