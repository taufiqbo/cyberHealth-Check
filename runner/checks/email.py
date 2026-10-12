"""EML-01..07: SPF, DMARC, DKIM, MTA-STS and TLS-RPT from DNS TXT records."""
import re

from ..net import NetError
from . import all_status, result

DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "k2", "s1", "s2", "mail", "dkim",
                  "smtp", "mxvault", "everlytickey1", "zoho", "protonmail", "mandrill", "sendgrid"]
SPF_LOOKUP_TERMS = re.compile(r"^(?:[+\-~?])?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)
MAX_SPF_LOOKUPS = 10


def _txt(net, name, prefix):
    return [r for r in net.resolve(name, "TXT") if r.lower().startswith(prefix)]


def _spf_lookups(net, record, depth=0, seen=None):
    """Counts DNS-querying SPF terms, following include: and redirect= (RFC 7208 section 4.6.4)."""
    seen = seen or set()
    count = 0
    for term in record.split()[1:]:
        if not SPF_LOOKUP_TERMS.match(term):
            continue
        count += 1
        if depth >= 5:
            continue
        lowered = term.lower().lstrip("+-~?")
        if lowered.startswith("include:") or lowered.startswith("redirect="):
            target = term.split(":", 1)[1] if ":" in term else term.split("=", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            try:
                nested = _txt(net, target, "v=spf1")
            except NetError:
                continue
            if nested:
                count += _spf_lookups(net, nested[0], depth + 1, seen)
    return count


def _tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def run(ctx):
    net, domain = ctx.net, ctx.target
    if ctx.is_ip:
        return all_status("email", "na", "Target is an IP address; email authentication applies to domains.")
    results = []
    try:
        mx = net.resolve(domain, "MX")
        spf = _txt(net, domain, "v=spf1")
        dmarc = _txt(net, f"_dmarc.{domain}", "v=dmarc1")
    except NetError as exc:
        return all_status("email", "inconclusive", f"DNS lookup failed: {exc}")
    ctx.evidence.update({"mx": mx, "spf": spf, "dmarc": dmarc})
    receives_mail = bool(mx) and mx != [""]

    # SPF
    if len(spf) == 1:
        results.append(result("EML-01", "pass", "One SPF record published.", {"spf": spf[0]}))
        record = spf[0]
        lookups = _spf_lookups(net, record)
        last = record.split()[-1].lower()
        detail = {"spf": record, "dns_lookups": lookups}
        if lookups > MAX_SPF_LOOKUPS:
            results.append(result("EML-02", "fail", f"SPF needs {lookups} DNS lookups (limit is 10).", detail))
        elif last == "-all":
            results.append(result("EML-02", "pass", f"SPF ends with -all ({lookups} lookups).", detail))
        elif last == "~all" or last.startswith("redirect="):
            results.append(result("EML-02", "partial", f"SPF ends with {last}; -all is stricter.", detail))
        else:
            results.append(result("EML-02", "fail", f"SPF ends with '{last}', which allows any sender.", detail))
    elif len(spf) > 1:
        results.append(result("EML-01", "fail", f"{len(spf)} SPF records published; receivers treat this as an error.",
                              {"spf": spf}))
        results.append(result("EML-02", "fail", "SPF is invalid because there is more than one record."))
    else:
        results.append(result("EML-01", "fail", "No SPF record."))
        results.append(result("EML-02", "fail", "No SPF record."))

    # DMARC
    if dmarc:
        tags = _tags(dmarc[0])
        results.append(result("EML-03", "pass", "DMARC record published.", {"dmarc": dmarc[0]}))
        policy = tags.get("p", "none").lower()
        pct_text = tags.get("pct", "100")
        pct = int(pct_text) if pct_text.isdigit() else 100
        detail = {"policy": policy, "pct": pct, "rua": tags.get("rua"), "sp": tags.get("sp")}
        if policy in ("reject", "quarantine") and pct == 100:
            results.append(result("EML-04", "pass", f"DMARC policy is {policy}.", detail))
        elif policy in ("reject", "quarantine"):
            results.append(result("EML-04", "partial", f"DMARC policy is {policy} but only for {pct}% of mail.", detail))
        else:
            results.append(result("EML-04", "fail", "DMARC policy is 'none' (monitoring only).", detail))
    else:
        results.append(result("EML-03", "fail", "No DMARC record at _dmarc." + domain))
        results.append(result("EML-04", "fail", "No DMARC record."))

    if not receives_mail:
        note = "Domain has no MX record (does not receive mail)."
        results.append(result("EML-05", "na", note + " A domain that sends no mail needs no DKIM."))
        results.append(result("EML-06", "na", note))
        results.append(result("EML-07", "na", note))
        return results

    # DKIM: selectors cannot be listed from outside, so only common ones are tried.
    found = {}
    for sel in DKIM_SELECTORS:
        try:
            recs = net.resolve(f"{sel}._domainkey.{domain}", "TXT")
            if not recs:
                recs = net.resolve(f"{sel}._domainkey.{domain}", "CNAME")
        except NetError:
            continue
        if recs:
            found[sel] = recs[0][:200]
    ctx.evidence["dkim"] = found
    if found:
        results.append(result("EML-05", "pass", "DKIM key found for selector(s): " + ", ".join(found), found))
    else:
        results.append(result("EML-05", "inconclusive",
                              "No DKIM key under common selectors. The selector may simply be unusual: "
                              "reviewer to check a mail header (DKIM-Signature s=) from the client.",
                              {"selectors_tried": DKIM_SELECTORS}))

    try:
        sts = _txt(net, f"_mta-sts.{domain}", "v=stsv1")
        rpt = _txt(net, f"_smtp._tls.{domain}", "v=tlsrptv1")
    except NetError as exc:
        results.append(result("EML-06", "inconclusive", f"DNS lookup failed: {exc}"))
        results.append(result("EML-07", "inconclusive", f"DNS lookup failed: {exc}"))
        return results
    results.append(result("EML-06", "pass" if sts else "fail",
                          "MTA-STS record published." if sts else "No MTA-STS record.", {"mta_sts": sts}))
    results.append(result("EML-07", "pass" if rpt else "fail",
                          "TLS-RPT record published." if rpt else "No TLS-RPT record.", {"tls_rpt": rpt}))
    return results
