"""BRD-01..04: lookalike domains (dnstwist) and registration health (RDAP)."""
import json
from datetime import datetime, timezone

from ..net import NetError
from . import all_status, result


def _lookalikes(ctx):
    tool = ctx.net.which("dnstwist")
    if not tool:
        raise NetError("dnstwist is not installed")
    rc, out, err = ctx.net.run([tool, "--registered", "--format", "json", ctx.target], timeout=1800)
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


def _rdap_result(ctx):
    try:
        data = ctx.net.rdap(ctx.target)
    except NetError as exc:
        return result("BRD-04", "inconclusive", f"RDAP lookup failed ({exc}). Reviewer to check WHOIS by hand.")
    expiry = None
    for event in data.get("events", []):
        if event.get("eventAction") == "expiration":
            expiry = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
    statuses = [s.lower() for s in data.get("status", [])]
    locked = any("transfer prohibited" in s for s in statuses)
    detail = {"expires": expiry.isoformat() if expiry else None, "status": statuses}
    if not expiry:
        return result("BRD-04", "inconclusive", "Registry did not publish an expiry date.", detail)
    days = (expiry - datetime.now(timezone.utc)).days
    if days < 30:
        return result("BRD-04", "fail", f"Domain expires in {days} day(s).", detail)
    if days < 60 or not locked:
        problems = ([f"expires in {days} days"] if days < 60 else []) + ([] if locked else ["no transfer lock"])
        return result("BRD-04", "partial", "Registration: " + ", ".join(problems) + ".", detail)
    return result("BRD-04", "pass", f"Expires in {days} days; transfer lock is on.", detail)


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
    results.append(_rdap_result(ctx))
    return results
