"""Everything that touches the network goes through a Net object, so demo mode and
the tests can swap in fixtures (see demo_net.py)."""
import ipaddress
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field

import dns.exception
import dns.query
import dns.resolver
import dns.xfr
import dns.zone
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "CyberHealthRunner/1.0 (external check; outside-in, not a penetration test)"


class NetError(Exception):
    pass


@dataclass
class HttpResponse:
    status: int
    headers: list  # [(name, value)], duplicates kept (Set-Cookie)
    body: str = ""
    url: str = ""
    tls_verified: bool = True

    def header(self, name):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class TlsInfo:
    ok: bool
    error: str = ""
    verified: bool = False
    verify_error: str = ""
    hostname_ok: bool = False
    version: str = ""
    cipher: str = ""
    cert: dict = field(default_factory=dict)


# Which weak modes the TLS module probes, and how to ask OpenSSL for them.
TLS_PROBES = {
    "TLSv1.0": ("TLSv1", None),
    "TLSv1.1": ("TLSv1_1", None),
    "RC4": (None, "RC4"),
    "3DES": (None, "3DES"),
    "NULL": (None, "eNULL"),
    "anonymous": (None, "aNULL"),
}
# Alerts that mean "the server said no", as opposed to "we could not ask".
_REFUSED = ("PROTOCOL_VERSION", "HANDSHAKE_FAILURE", "UNSUPPORTED_PROTOCOL", "WRONG_VERSION_NUMBER",
            "INSUFFICIENT_SECURITY", "NO_SHARED_CIPHER", "INTERNAL_ERROR", "ILLEGAL_PARAMETER")
_LOCAL = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH")


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def decode_der(der):
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = ""
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = sans.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    try:
        issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        issuer = cert.issuer.rfc4514_string()
    return {
        "subject_cn": cn,
        "sans": list(names),
        "issuer": issuer,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "self_signed": cert.issuer == cert.subject,
    }


class LiveNet:
    demo = False

    def __init__(self, config, allow_private=False):
        self.config = config
        self.allow_private = allow_private
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 8
        self.resolver.timeout = 4

    # DNS -------------------------------------------------------------------
    def resolve(self, name, rtype):
        """Records as text. [] when the name or type does not exist; NetError on failure."""
        try:
            answer = self.resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise NetError(f"DNS {rtype} {name}: {exc.__class__.__name__}") from exc
        out = []
        for rr in answer:
            if rtype == "TXT":
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            elif rtype == "MX":
                out.append(str(rr.exchange).rstrip("."))
            else:
                out.append(rr.to_text().rstrip("."))
        return out

    def nxdomain(self, name):
        """True if the name does not exist at all, False if it does, None if DNS failed."""
        try:
            self.resolver.resolve(name, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except dns.resolver.NoAnswer:
            return False
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return None

    def axfr_allowed(self, domain, nameserver):
        try:
            ips = self.resolve(nameserver, "A")
            if not ips:
                return None
            zone = dns.zone.from_xfr(dns.query.xfr(ips[0], domain, lifetime=10))
            return len(zone.nodes) > 0
        except dns.exception.FormError:
            return False
        except (dns.xfr.TransferError, EOFError, ConnectionError, OSError):
            return False
        except Exception:
            return None

    # HTTP ------------------------------------------------------------------
    def _guard(self, host):
        if self.allow_private:
            return
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise NetError(f"{host} does not resolve") from exc
        for info in infos:
            if not is_public_ip(info[4][0]):
                raise NetError(f"{host} resolves to a non-public address ({info[4][0]}); not contacted")

    def http(self, method, url, timeout=10, max_body=200_000):
        host = requests.utils.urlparse(url).hostname
        self._guard(host)
        headers = {"User-Agent": USER_AGENT}
        verified = True
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout,
                                    allow_redirects=False, stream=True)
        except requests.exceptions.SSLError:
            verified = False
            try:
                resp = requests.request(method, url, headers=headers, timeout=timeout,
                                        allow_redirects=False, stream=True, verify=False)
            except requests.RequestException as exc:
                raise NetError(f"{method} {url}: {exc.__class__.__name__}") from exc
        except requests.RequestException as exc:
            raise NetError(f"{method} {url}: {exc.__class__.__name__}") from exc
        body = ""
        if method != "HEAD":
            raw = resp.raw.read(max_body, decode_content=True) or b""
            body = raw.decode(resp.encoding or "utf-8", "replace")
        header_list = list(resp.raw.headers.items())
        resp.close()
        return HttpResponse(resp.status_code, header_list, body, url, verified)

    def get_json(self, url, headers=None, timeout=30):
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT, **(headers or {})}, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise NetError(f"GET {url}: {exc}") from exc

    # TLS -------------------------------------------------------------------
    def tls_handshake(self, host, port=443, timeout=8):
        try:
            self._guard(host)
        except NetError as exc:
            return TlsInfo(ok=False, error=str(exc))
        info = TlsInfo(ok=False)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    info.ok = info.verified = info.hostname_ok = True
                    info.version = tls.version()
                    info.cipher = tls.cipher()[0]
                    info.cert = decode_der(tls.getpeercert(binary_form=True))
                    return info
        except ssl.SSLCertVerificationError as exc:
            info.verify_error = exc.verify_message or str(exc)
            info.hostname_ok = "hostname" not in info.verify_error.lower() and "IP address mismatch" not in info.verify_error
        except (OSError, ssl.SSLError) as exc:
            return TlsInfo(ok=False, error=f"{exc.__class__.__name__}: {exc}")
        # Certificate did not verify: connect again without verification to read it.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    info.ok = True
                    info.version = tls.version()
                    info.cipher = tls.cipher()[0]
                    info.cert = decode_der(tls.getpeercert(binary_form=True))
        except (OSError, ssl.SSLError) as exc:
            info.error = f"{exc.__class__.__name__}: {exc}"
        return info

    def tls_accepts(self, host, probe, port=443, timeout=8):
        """True if the server accepts the weak protocol/cipher, False if it refuses,
        None if this machine's OpenSSL cannot make the attempt (or the network failed)."""
        version_name, cipher = TLS_PROBES[probe]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            if version_name:
                version = getattr(ssl.TLSVersion, version_name)
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            else:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 has no weak suites
                ctx.set_ciphers(f"{cipher}:@SECLEVEL=0")
        except (ssl.SSLError, ValueError, AttributeError):
            return None
        try:
            self._guard(host)
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except ssl.SSLError as exc:
            text = f"{exc.reason or ''} {exc}".upper()
            if any(k in text for k in _LOCAL):
                return None
            if any(k in text for k in _REFUSED):
                return False
            return None
        except ConnectionResetError:
            return False  # many servers just drop the connection
        except (OSError, NetError):
            return None

    # Certificate transparency ---------------------------------------------
    def ct_names(self, domain):
        """Host names seen in certificate transparency logs. Returns (names, source)."""
        errors = []
        try:
            data = self.get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=60)
            names = set()
            for entry in data:
                for n in str(entry.get("name_value", "")).splitlines():
                    names.add(n.strip().lower())
            return sorted(names), "crt.sh"
        except NetError as exc:
            errors.append(str(exc))
        try:
            data = self.get_json(
                f"https://api.certspotter.com/v1/issuances?domain={domain}"
                "&include_subdomains=true&expand=dns_names", timeout=60)
            names = {n.lower() for entry in data for n in entry.get("dns_names", [])}
            return sorted(names), "certspotter"
        except NetError as exc:
            errors.append(str(exc))
        raise NetError("; ".join(errors))

    def rdap(self, domain):
        return self.get_json(f"https://rdap.org/domain/{domain}", timeout=30)

    # External tools ---------------------------------------------------------
    def which(self, tool):
        return shutil.which(self.config.tool_paths.get(tool, tool))

    def run(self, argv, timeout=1800):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise NetError(f"{argv[0]} timed out after {timeout}s") from exc
        except OSError as exc:
            raise NetError(f"{argv[0]}: {exc}") from exc
        return proc.returncode, proc.stdout, proc.stderr
