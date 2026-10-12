"""EAS-01..05: what the internet can see of the domain (CT logs, Amass, DNS)."""
import re
from concurrent.futures import ThreadPoolExecutor

from ..net import NetError, is_public_ip
from . import all_status, result

COMMON_NAMES = ["www", "mail", "webmail", "remote", "vpn", "portal", "owa", "autodiscover", "api", "app",
                "dev", "test", "staging", "uat", "admin", "cpanel", "ftp", "intranet", "shop", "blog"]
NONPROD = re.compile(r"(^|[.-])(dev|develop|test|testing|stage|staging|uat|qa|sandbox|beta|preprod|old|"
                     r"backup|admin|cpanel|whm|phpmyadmin|jenkins|gitlab|grafana|kibana|webmin)\d*([.-]|$)")
# Services where a CNAME to a deleted resource can be claimed by anyone.
TAKEOVER_SUFFIXES = (
    ".s3.amazonaws.com", ".s3-website", ".cloudfront.net", ".elasticbeanstalk.com", ".azurewebsites.net",
    ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net",
    ".azureedge.net", ".herokuapp.com", ".herokudns.com", ".github.io", ".pantheonsite.io",
    ".myshopify.com", ".wpengine.com", ".zendesk.com", ".netlify.app", ".ghost.io", ".surge.sh",
    ".bitbucket.io", ".readthedocs.io", ".unbouncepages.com", ".helpscoutdocs.com", ".fly.dev",
)
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_NAMES = 400


def _in_scope(name, domain):
    return name == domain or name.endswith("." + domain)


def _clean(name, domain):
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if HOSTNAME_RE.match(name) and _in_scope(name, domain):
        return name
    return None


def _lookup(net, name):
    entry = {"name": name, "cname": [], "a": [], "aaaa": [], "error": None}
    try:
        entry["cname"] = net.resolve(name, "CNAME")
        entry["a"] = net.resolve(name, "A")
        entry["aaaa"] = net.resolve(name, "AAAA")
    except NetError as exc:
        entry["error"] = str(exc)
    entry["resolves"] = bool(entry["a"] or entry["aaaa"])
    return entry


def _zone_apex(net, domain):
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        ns = net.resolve(candidate, "NS")
        if ns:
            return candidate, ns
    return domain, []


def run(ctx):
    net, domain = ctx.net, ctx.target
    if ctx.is_ip:
        ctx.evidence.update({"hosts": [], "web_hosts": [domain], "primary_host": domain, "scan_scope": [domain]})
        return all_status("discovery", "na", "Target is an IP address; DNS-based discovery does not apply.")

    names = {domain, f"www.{domain}"}
    sources = {}
    try:
        ct, source = net.ct_names(domain)
        found = {n for n in (_clean(x, domain) for x in ct) if n}
        names |= found
        sources["certificate_transparency"] = {"source": source, "names": len(found)}
    except NetError as exc:
        sources["certificate_transparency"] = {"error": str(exc)}

    amass = net.which("amass")
    if amass:
        try:
            rc, out, err = net.run([amass, "enum", "-passive", "-d", domain, "-timeout", "10"], timeout=900)
            found = {n for n in (_clean(line.split()[0], domain) for line in out.splitlines() if line.strip()) if n}
            names |= found
            sources["amass"] = {"names": len(found), "exit_code": rc}
        except NetError as exc:
            sources["amass"] = {"error": str(exc)}
    else:
        sources["amass"] = {"skipped": "amass not installed"}

    names |= {f"{n}.{domain}" for n in COMMON_NAMES}
    ordered = sorted(names, key=lambda n: (n != domain, n != f"www.{domain}", n))[:MAX_NAMES]
    with ThreadPoolExecutor(max_workers=16) as pool:
        hosts = list(pool.map(lambda n: _lookup(net, n), ordered))
    # Names guessed from the common list only count if they exist.
    guessed = {f"{n}.{domain}" for n in COMMON_NAMES}
    hosts = [h for h in hosts if h["name"] not in guessed or h["resolves"] or h["cname"]]
    resolving = [h for h in hosts if h["resolves"]]
    dns_errors = [h for h in hosts if h["error"]]

    by_name = {h["name"]: h for h in hosts}
    primary = domain if by_name.get(domain, {}).get("resolves") else f"www.{domain}"
    web_hosts = [h["name"] for h in sorted(resolving, key=lambda h: (h["name"] != primary,
                                                                    h["name"] != f"www.{domain}", h["name"]))]
    web_hosts = web_hosts[:ctx.config.max_web_hosts] or [primary]
    scope = []
    for name in (domain, f"www.{domain}"):
        for ip in by_name.get(name, {}).get("a", []) + by_name.get(name, {}).get("aaaa", []):
            if (is_public_ip(ip) or ctx.net.demo) and ip not in scope:
                scope.append(ip)
    scope = scope[:ctx.config.max_scan_hosts]
    ctx.evidence.update({"sources": sources, "hosts": hosts, "web_hosts": web_hosts,
                         "primary_host": primary, "scan_scope": scope})
    results = []

    # EAS-01
    ct_ok = "error" not in sources["certificate_transparency"]
    inventory = {"hostnames_found": len(hosts), "hostnames_resolving": len(resolving),
                 "resolving": [h["name"] for h in resolving][:200], "sources": sources}
    if ct_ok or "names" in sources.get("amass", {}):
        results.append(result("EAS-01", "pass",
                              f"Inventory built: {len(hosts)} host names found, {len(resolving)} resolve.", inventory))
    else:
        results.append(result("EAS-01", "inconclusive",
                              "Certificate transparency could not be reached and Amass is not installed; "
                              f"only common names were checked ({len(resolving)} resolve).", inventory))

    # EAS-02
    dangling = []
    for h in hosts:
        if not h["cname"]:
            continue
        target = h["cname"][-1].lower()
        gone = net.nxdomain(target)
        risky = any(s in target for s in TAKEOVER_SUFFIXES)
        if gone or (risky and not h["resolves"]):
            dangling.append({"name": h["name"], "cname": target, "target_missing": bool(gone)})
    if dangling:
        results.append(result("EAS-02", "fail",
                              f"{len(dangling)} record(s) point to missing resources: "
                              + ", ".join(d["name"] for d in dangling[:5]), {"dangling": dangling}))
    elif len(dns_errors) > len(hosts) / 2:
        results.append(result("EAS-02", "inconclusive", "Too many DNS lookups failed to judge.",
                              {"dns_errors": len(dns_errors)}))
    else:
        results.append(result("EAS-02", "pass", "No dangling CNAME records found."))

    # EAS-03
    exposed = [h["name"] for h in resolving if NONPROD.search(h["name"][: -len(domain)])]
    if exposed:
        results.append(result("EAS-03", "partial",
                              f"{len(exposed)} test/admin-style host name(s) resolve publicly: "
                              + ", ".join(exposed[:5]) + ". Reviewer to confirm whether they are protected.",
                              {"hosts": exposed}, review=True))
    else:
        results.append(result("EAS-03", "pass", "No test, staging or admin host names resolve publicly."))

    # EAS-04 and EAS-05
    try:
        apex, ns = _zone_apex(net, domain)
        ds = net.resolve(apex, "DS")
        results.append(result("EAS-04", "pass" if ds else "fail",
                              f"DNSSEC {'is' if ds else 'is not'} enabled for {apex}.", {"zone": apex, "ds": ds}))
        axfr = {n: net.axfr_allowed(apex, n) for n in ns[:4]}
        open_ns = [n for n, v in axfr.items() if v]
        detail = {"zone": apex, "nameservers": ns, "zone_transfer": axfr}
        if open_ns:
            results.append(result("EAS-05", "fail", f"Zone transfer allowed by {', '.join(open_ns)}.", detail))
        elif len(ns) < 2:
            results.append(result("EAS-05", "fail", f"Only {len(ns)} name server found.", detail))
        elif not any(v is False for v in axfr.values()):
            results.append(result("EAS-05", "inconclusive",
                                  f"{len(ns)} name servers; zone transfer test did not complete.", detail))
        else:
            results.append(result("EAS-05", "pass", f"{len(ns)} name servers; zone transfers refused.", detail))
    except NetError as exc:
        results.append(result("EAS-04", "inconclusive", f"DNS lookup failed: {exc}"))
        results.append(result("EAS-05", "inconclusive", f"DNS lookup failed: {exc}"))
    return results
