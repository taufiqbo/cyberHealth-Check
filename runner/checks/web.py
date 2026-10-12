"""WEB-01..08 and VUL-05: HTTP GET of the home page and /.well-known/security.txt."""
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlparse

from ..net import NetError
from . import result

GOOD_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin"}
VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]
HAS_VERSION = re.compile(r"\d+\.\d+")
MAX_HOPS = 5


def _in_scope(host, ctx):
    if not host:
        return False
    host = host.lower()
    return host == ctx.target or host.endswith("." + ctx.target)


def fetch_home(ctx, host):
    """GET the home page, following redirects that stay inside the assessed domain."""
    chain, notes = [], []
    url = f"https://{host}/"
    try:
        resp = ctx.net.http("GET", url)
    except NetError as exc:
        notes.append(f"HTTPS failed ({exc}); tried HTTP.")
        url = f"http://{host}/"
        resp = ctx.net.http("GET", url)
    chain.append(resp)
    for _ in range(MAX_HOPS):
        location = resp.header("Location")
        if resp.status not in (301, 302, 303, 307, 308) or not location:
            break
        nxt = urljoin(resp.url, location)
        if not _in_scope(urlparse(nxt).hostname, ctx):
            notes.append(f"Redirects outside the assessed domain to {nxt}; not followed.")
            break
        resp = ctx.net.http("GET", nxt)
        chain.append(resp)
    return chain, notes


def _csp_result(csp, report_only):
    if not csp:
        if report_only:
            return result("WEB-01", "partial", "CSP is report-only; it does not block anything yet.",
                          {"csp_report_only": report_only})
        return result("WEB-01", "fail", "No Content-Security-Policy header.")
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    script = directives.get("script-src", directives.get("default-src", []))
    weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in script]
    nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
    if "'unsafe-inline'" in weak and nonce_or_hash:
        weak.remove("'unsafe-inline'")  # ignored by browsers when a nonce or hash is present
    if not script:
        return result("WEB-01", "partial", "CSP is set but does not restrict scripts.", {"csp": csp})
    if weak:
        return result("WEB-01", "partial", "CSP allows " + " and ".join(weak) + " for scripts.", {"csp": csp})
    return result("WEB-01", "pass", "Content-Security-Policy restricts scripts.", {"csp": csp})


def _cookie_result(cookies):
    if not cookies:
        return result("WEB-06", "na", "The home page sets no cookies.")
    problems = {}
    worst = "pass"
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=")[0].lower() for a in raw.split(";")[1:]}
        missing = [flag for flag, key in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if key not in attrs]
        if missing:
            problems[name] = missing
            if "Secure" in missing:
                worst = "fail"
            elif worst == "pass":
                worst = "partial"
    if not problems:
        return result("WEB-06", "pass", f"All {len(cookies)} cookie(s) have Secure, HttpOnly and SameSite.")
    text = "; ".join(f"{n} missing {', '.join(m)}" for n, m in list(problems.items())[:5])
    return result("WEB-06", worst, text, {"cookies": problems})


def _security_txt(ctx):
    host = ctx.target
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = ctx.net.http("GET", f"https://{host}{path}")
        except NetError:
            continue
        if resp.status != 200 or not re.search(r"^contact:", resp.body, re.I | re.M):
            continue
        detail = {"url": f"https://{host}{path}", "content": resp.body[:2000]}
        m = re.search(r"^expires:\s*(\S+)", resp.body, re.I | re.M)
        if not m:
            return result("VUL-05", "partial", "security.txt found but has no Expires field.", detail)
        try:
            expires = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except ValueError:
            return result("VUL-05", "partial", "security.txt Expires field cannot be read.", detail)
        if expires < datetime.now(timezone.utc):
            return result("VUL-05", "partial", f"security.txt expired on {expires.date()}.", detail)
        return result("VUL-05", "pass", f"security.txt published (expires {expires.date()}).", detail)
    return result("VUL-05", "fail", "No security.txt at /.well-known/security.txt.")


def run(ctx):
    host = ctx.primary_host()
    try:
        chain, notes = fetch_home(ctx, host)
    except NetError as exc:
        results = [result(cid, "inconclusive", f"Home page could not be fetched: {exc}")
                   for cid in ("WEB-01", "WEB-03", "WEB-04", "WEB-05", "WEB-06", "WEB-07", "WEB-08")]
        results.append(result("WEB-02", "review", f"Home page could not be fetched: {exc}. Reviewer to check by hand."))
        results.append(_security_txt(ctx))
        return results
    final = chain[-1]
    cookies = [c for r in chain for c in r.header_all("Set-Cookie")]
    ctx.evidence["chain"] = [{"url": r.url, "status": r.status, "headers": r.headers} for r in chain]
    ctx.evidence["notes"] = notes
    banners = []
    for r in chain:
        for name in VERSION_HEADERS:
            for value in r.header_all(name):
                banners.append({"host": urlparse(r.url).hostname, "header": name, "value": value})
    ctx.evidence["banners"] = banners
    results = []

    csp = final.header("Content-Security-Policy")
    results.append(_csp_result(csp, final.header("Content-Security-Policy-Report-Only")))

    title = re.search(r"<title[^>]*>(.*?)</title>", final.body, re.I | re.S)
    title_text = unescape(title.group(1)).strip()[:200] if title else ""
    results.append(result("WEB-02", "review",
                          f"Home page {final.url} returned {final.status}"
                          + (f" with title '{title_text}'." if title_text else " with no title.")
                          + " Screenshot not taken automatically: reviewer to open the page and check it.",
                          {"url": final.url, "status": final.status, "title": title_text, "notes": notes}))

    xfo = (final.header("X-Frame-Options") or "").upper()
    frame_ancestors = csp and "frame-ancestors" in csp.lower()
    if xfo in ("DENY", "SAMEORIGIN") or frame_ancestors:
        results.append(result("WEB-03", "pass", "Framing is restricted.", {"x_frame_options": xfo}))
    else:
        results.append(result("WEB-03", "fail", "No X-Frame-Options or CSP frame-ancestors."))

    nosniff = (final.header("X-Content-Type-Options") or "").lower() == "nosniff"
    results.append(result("WEB-04", "pass" if nosniff else "fail",
                          "X-Content-Type-Options: nosniff is set." if nosniff else "X-Content-Type-Options is missing."))

    referrer = (final.header("Referrer-Policy") or "").lower()
    policies = {p.strip() for p in referrer.split(",") if p.strip()}
    if policies & GOOD_REFERRER and "unsafe-url" not in policies:
        results.append(result("WEB-05", "pass", f"Referrer-Policy: {referrer}."))
    elif "unsafe-url" in policies:
        results.append(result("WEB-05", "fail", "Referrer-Policy is unsafe-url (full URLs leak to other sites)."))
    else:
        results.append(result("WEB-05", "partial", "No Referrer-Policy header (browser default applies)."))

    results.append(_cookie_result(cookies))

    leaking = [f"{b['header']}: {b['value']}" for b in banners if HAS_VERSION.search(b["value"])]
    if leaking:
        results.append(result("WEB-07", "fail", "Versions disclosed: " + "; ".join(sorted(set(leaking))[:5]),
                              {"banners": banners}))
    else:
        results.append(result("WEB-07", "pass", "No software versions in response headers.", {"banners": banners}))

    pp = final.header("Permissions-Policy") or final.header("Feature-Policy")
    results.append(result("WEB-08", "pass" if pp else "fail",
                          "Permissions-Policy is set." if pp else "No Permissions-Policy header."))

    results.append(_security_txt(ctx))
    return results
