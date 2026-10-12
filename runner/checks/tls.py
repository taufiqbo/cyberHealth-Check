"""TLS-01..07: handshakes on 443 and HTTP HEAD for redirect and HSTS."""
import re
from datetime import datetime, timezone

from ..net import NetError
from . import result

HSTS_MIN = 15552000  # 180 days
MAX_PROBE_HOSTS = 5


def _days_left(not_after):
    end = datetime.fromisoformat(not_after)
    return (end - datetime.now(timezone.utc)).days


def _probe(net, hosts, probes):
    found, untestable, per_host = [], set(), {}
    for host in hosts:
        per_host[host] = {}
        for probe in probes:
            accepted = net.tls_accepts(host, probe)
            per_host[host][probe] = accepted
            if accepted:
                found.append(f"{host}: {probe}")
            elif accepted is None:
                untestable.add(probe)
    return found, sorted(untestable), per_host


def _probe_result(control_id, label, found, untestable, per_host):
    detail = {"per_host": per_host, "not_testable_here": untestable}
    if found:
        return result(control_id, "fail", f"Accepted {label}: " + "; ".join(found[:6]), detail)
    if untestable:
        return result(control_id, "inconclusive",
                      f"Could not test {', '.join(untestable)} from this server's OpenSSL. "
                      "Confirm with: nmap --script ssl-enum-ciphers -p 443 <host>", detail)
    return result(control_id, "pass", f"No {label} accepted.", detail)


def _redirect_and_hsts(net, host):
    detail = {}
    try:
        plain = net.http("HEAD", f"http://{host}/")
        location = plain.header("Location") or ""
        detail["http_status"] = plain.status
        detail["http_location"] = location
        redirect_ok = plain.status in (301, 302, 307, 308) and location.lower().startswith("https://")
    except NetError as exc:
        # Nothing listening on port 80 means no plain HTTP to downgrade to.
        detail["http_error"] = str(exc)
        redirect_ok = True
    hsts_ok = False
    try:
        secure = net.http("HEAD", f"https://{host}/")
        hsts = secure.header("Strict-Transport-Security") or ""
        detail["hsts"] = hsts
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        hsts_ok = bool(m and int(m.group(1)) >= HSTS_MIN)
    except NetError as exc:
        detail["https_error"] = str(exc)
    return redirect_ok, hsts_ok, detail


def run(ctx):
    net = ctx.net
    primary = ctx.primary_host()
    hosts = ctx.web_hosts()
    infos = {h: net.tls_handshake(h) for h in hosts}
    handshakes = {h: {"ok": i.ok, "error": i.error, "verified": i.verified, "verify_error": i.verify_error,
                      "hostname_ok": i.hostname_ok, "version": i.version, "cipher": i.cipher, "cert": i.cert}
                  for h, i in infos.items()}
    ctx.evidence["handshakes"] = handshakes
    up = {h: i for h, i in infos.items() if i.ok}
    results = []

    primary_info = infos.get(primary)
    if primary_info and primary_info.ok:
        results.append(result("TLS-01", "pass", f"HTTPS answers on {primary} ({primary_info.version}).",
                              {"hosts_with_https": sorted(up)}))
    else:
        err = primary_info.error if primary_info else "not checked"
        results.append(result("TLS-01", "fail", f"No HTTPS on {primary}: {err}", {"hosts_with_https": sorted(up)}))
    if not up:
        for cid in ("TLS-02", "TLS-03", "TLS-04", "TLS-05", "TLS-06", "TLS-07"):
            results.append(result(cid, "na", "No host answered on port 443."))
        return results

    untrusted = {h: i.verify_error for h, i in up.items()
                 if not i.verified and (i.hostname_ok or i.cert.get("self_signed"))}
    if untrusted:
        results.append(result("TLS-02", "fail", "Untrusted certificate on " + ", ".join(sorted(untrusted)),
                              {"errors": untrusted}))
    else:
        results.append(result("TLS-02", "pass", f"Trusted certificate chain on all {len(up)} HTTPS host(s)."))

    expiry = {h: _days_left(i.cert["not_after"]) for h, i in up.items() if i.cert.get("not_after")}
    if expiry:
        soonest_host = min(expiry, key=expiry.get)
        days = expiry[soonest_host]
        status = "pass" if days > 30 else "partial" if days > 7 else "fail"
        text = (f"Certificate on {soonest_host} expired {-days} day(s) ago." if days < 0 else
                f"Soonest expiry: {soonest_host} in {days} day(s).")
        results.append(result("TLS-03", status, text, {"days_left": expiry}))
    else:
        results.append(result("TLS-03", "inconclusive", "Could not read certificate dates."))

    if ctx.is_ip:
        results.append(result("TLS-04", "na", "Target is an IP address; certificates name host names."))
    else:
        mismatch = sorted(h for h, i in up.items() if not i.hostname_ok)
        if mismatch:
            results.append(result("TLS-04", "fail", "Certificate does not cover: " + ", ".join(mismatch),
                                  {h: up[h].cert.get("sans") for h in mismatch}))
        else:
            results.append(result("TLS-04", "pass", "Certificates match their host names."))

    probe_hosts = [primary] if primary in up else []
    probe_hosts += [h for h in up if h != primary][:MAX_PROBE_HOSTS - len(probe_hosts)]
    found, untestable, per_host = _probe(net, probe_hosts, ["TLSv1.0", "TLSv1.1"])
    results.append(_probe_result("TLS-05", "old protocols", found, untestable, per_host))
    found, untestable, per_host = _probe(net, probe_hosts, ["RC4", "3DES", "NULL", "anonymous"])
    results.append(_probe_result("TLS-06", "weak ciphers", found, untestable, per_host))

    host = primary if primary in up else next(iter(up))
    redirect_ok, hsts_ok, detail = _redirect_and_hsts(net, host)
    ctx.evidence["redirect_hsts"] = detail
    if redirect_ok and hsts_ok:
        results.append(result("TLS-07", "pass", f"{host}: HTTP redirects to HTTPS and HSTS is set.", detail))
    elif redirect_ok or hsts_ok:
        missing = "HSTS (180 days or more)" if redirect_ok else "an HTTP to HTTPS redirect"
        results.append(result("TLS-07", "partial", f"{host}: missing {missing}.", detail))
    else:
        results.append(result("TLS-07", "fail", f"{host}: no HTTPS redirect and no HSTS.", detail))
    return results
