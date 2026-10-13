"""BRD-01..04: lookalike domains (dnstwist) and registration health (RDAP, or WHOIS where there is no RDAP)."""
import json
import re
from datetime import datetime, timezone

from ..net import NetError
from . import all_status, result


def _lookalikes(ctx):
    argv = ctx.net.tool_argv("dnstwist")
    if not argv:
        raise NetError("dnstwist is not installed (pip install dnstwist)")
    ctx.progress("running dnstwist (lookalike domains; can take 10+ minutes)")
    rc, out, err = ctx.net.run([*argv, "--registered", "--format", "json", ctx.target], timeout=1800)
    if rc != 0 and not out.strip():
        raise NetError(f"dnstwist failed: {err.strip()[:300]}")
    try:
        rows = json.loads(out)
    except ValueError as exc:
        raise NetError("dnstwist output could not be read") from exc
    out_rows = []
    for row in rows:
        if row.get("fuzzer") == "*original" or row.get("domain") == ctx.target:
            continue
        out_rows.append({
            "domain": row.get("domain", row.get("domain-name")),
            "fuzzer": row.get("fuzzer"),
            "a": row.get("dns_a", row.get("dns-a", [])),
            "mx": [m for m in row.get("dns_mx", row.get("dns-mx", [])) if m and m != "!ServFail"],
        })
    return out_rows


MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                        "nov", "dec"], 1)}


def _whois_date(line):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", line)
    if m:
        return datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc)
    m = re.search(r"(\d{1,2})[- ]([A-Za-z]{3})[a-z]*[- ](\d{4})", line)
    if m and m[2].lower() in MONTHS:
        return datetime(int(m[3]), MONTHS[m[2].lower()], int(m[1]), tzinfo=timezone.utc)
    return None


def parse_whois(text):
    """Returns (expiry or None, locked True/False/None). None for locked means the registry shows no status."""
    expiry = None
    for line in text.splitlines():
        if re.search(r"expir", line, re.I):
            expiry = _whois_date(line)
            if expiry:
                break
    squashed = re.sub(r"[\s_-]", "", text.lower())
    if "transferprohibited" in squashed:
        locked = True
    elif re.search(r"^\s*(domain )?status\s*:", text, re.I | re.M):
        locked = False
    else:
        locked = None
    return expiry, locked


def _registration(ctx):
    """(expiry, locked, source, detail) from RDAP, else WHOIS."""
    ctx.progress("RDAP registration lookup")
    try:
        data = ctx.net.rdap(ctx.target)
        expiry = None
        for event in data.get("events", []):
            if event.get("eventAction") == "expiration":
                expiry = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
        statuses = [s.lower() for s in data.get("status", [])]
        locked = any("transfer prohibited" in s for s in statuses) if statuses else None
        return expiry, locked, "RDAP", {"status": statuses}
    except NetError as rdap_error:
        ctx.progress("RDAP has no record; trying WHOIS")
        try:
            server, text = ctx.net.whois(ctx.target)
        except NetError as exc:
            raise NetError(f"RDAP: {rdap_error}; WHOIS: {exc}") from exc
        expiry, locked = parse_whois(text)
        return expiry, locked, f"WHOIS ({server})", {"whois": text[:3000]}


def _registration_result(ctx):
    try:
        expiry, locked, source, detail = _registration(ctx)
    except NetError as exc:
        return result("BRD-04", "inconclusive", f"Registration lookup failed ({exc}). Reviewer to check WHOIS by hand.")
    detail = {"source": source, "expires": expiry.isoformat() if expiry else None, "transfer_lock": locked, **detail}
    if not expiry:
        return result("BRD-04", "inconclusive", f"{source} did not show an expiry date. Reviewer to check by hand.",
                      detail)
    days = (expiry - datetime.now(timezone.utc)).days
    lock_note = {True: "transfer lock is on", False: "no transfer lock",
                 None: "registry does not publish the transfer lock"}[locked]
    if days < 30:
        return result("BRD-04", "fail", f"Domain expires in {days} day(s) ({source}).", detail)
    problems = ([f"expires in {days} days"] if days < 60 else []) + (["no transfer lock"] if locked is False else [])
    if problems:
        return result("BRD-04", "partial", f"Registration ({source}): " + ", ".join(problems) + ".", detail)
    return result("BRD-04", "pass", f"Expires in {days} days; {lock_note} ({source}).", detail, review=locked is None)


def run(ctx):
    if ctx.is_ip:
        return all_status("brand", "na", "Target is an IP address; brand checks apply to domains.")
    results = []
    try:
        rows = _lookalikes(ctx)
    except NetError as exc:
        results += [result(cid, "inconclusive", str(exc)) for cid in ("BRD-01", "BRD-02", "BRD-03")]
    else:
        ctx.evidence["lookalikes"] = rows
        live = [r for r in rows if r["a"]]
        mail = [r for r in rows if r["mx"]]
        if live:
            results.append(result("BRD-01", "review",
                                  f"{len(live)} lookalike domain(s) have a website address. Screenshots are not taken "
                                  "automatically: reviewer to open them and check for copies of the client's site.",
                                  {"live": [r["domain"] for r in live][:50]}))
        else:
            results.append(result("BRD-01", "pass", "No live lookalike websites found."))
        n = len(rows)
        status = "pass" if n == 0 else "partial" if n <= 10 else "fail"
        results.append(result("BRD-02", status, f"{n} lookalike domain(s) registered.",
                              {"registered": [r["domain"] for r in rows][:100]}))
        if mail:
            results.append(result("BRD-03", "fail",
                                  f"{len(mail)} lookalike domain(s) can receive email: "
                                  + ", ".join(r["domain"] for r in mail[:5])
                                  + ". Reviewer to exclude any the client owns.",
                                  {"mail_capable": [{"domain": r["domain"], "mx": r["mx"]} for r in mail]}, review=True))
        else:
            results.append(result("BRD-03", "pass", "No lookalike domain has mail servers."))
    results.append(_registration_result(ctx))
    return results
