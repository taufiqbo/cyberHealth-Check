"""SVC-01..05: Nmap, run twice. Pass one finds open ports; pass two re-checks them and
reads service versions. Only ports open in both passes count as confirmed."""
from defusedxml import DefusedXmlException, ElementTree

from ..net import NetError, is_public_ip
from . import all_status, result

HIGH_RISK = {23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin",
             514: "rsh", 3389: "RDP", 5900: "VNC", 5901: "VNC", 5902: "VNC", 6000: "X11"}
DATABASES = {1433: "MS SQL", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 5432: "PostgreSQL",
             5984: "CouchDB", 6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch", 9300: "Elasticsearch",
             11211: "Memcached", 27017: "MongoDB"}
CLEARTEXT = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP", 513: "rlogin", 514: "rsh",
             1883: "MQTT"}
MANAGEMENT = {2082, 2083, 2086, 2087, 2095, 2096, 3000, 4443, 5000, 5001, 7001, 8000, 8006, 8080, 8081,
              8088, 8090, 8443, 8834, 8888, 9000, 9090, 9443, 10000}
WEB_DEFAULT = {80, 443}


def parse_nmap(xml_text):
    """Returns {ip: {port: {state, service, product, version, tunnel}}} for TCP ports."""
    root = ElementTree.fromstring(xml_text)
    hosts = {}
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        ports = hosts.setdefault(addr, {})
        for port in host.iter("port"):
            if port.get("protocol") != "tcp":
                continue
            state = port.find("state")
            svc = port.find("service")
            ports[int(port.get("portid"))] = {
                "state": state.get("state") if state is not None else "unknown",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "tunnel": svc.get("tunnel", "") if svc is not None else "",
            }
    return hosts


def _open(hosts):
    return {ip: {p: v for p, v in ports.items() if v["state"] == "open"} for ip, ports in hosts.items()}


def run(ctx):
    scope = [ip for ip in ctx.assessment.get("headsup_scope_list", []) if is_public_ip(ip) or ctx.net.demo]
    if not scope:
        return all_status("services", "inconclusive", "No addresses in the confirmed scan scope.")
    nmap = ctx.net.which("nmap")
    if not nmap:
        return all_status("services", "inconclusive", "Nmap is not installed on this server.")
    try:
        rc, out1, err = ctx.net.run([nmap, "-Pn", "-sT", "--top-ports", "1000", "-T3", "--open", "-oX", "-", *scope])
        if rc != 0:
            raise NetError(f"nmap pass 1 exit {rc}: {err.strip()[:300]}")
        first = _open(parse_nmap(out1))
        ports = sorted({p for host in first.values() for p in host})
        second = {}
        if ports:
            rc, out2, err = ctx.net.run([nmap, "-Pn", "-sT", "-sV", "--version-light", "-T3",
                                         "-p", ",".join(map(str, ports)), "-oX", "-", *scope])
            if rc != 0:
                raise NetError(f"nmap pass 2 exit {rc}: {err.strip()[:300]}")
            second = _open(parse_nmap(out2))
    except (NetError, ElementTree.ParseError, DefusedXmlException) as exc:
        return all_status("services", "inconclusive", f"Nmap did not complete: {exc}")

    confirmed, unconfirmed = [], []
    for ip, ports_open in first.items():
        for port in ports_open:
            svc = second.get(ip, {}).get(port)
            entry = {"ip": ip, "port": port, **(svc or ports_open[port])}
            (confirmed if svc else unconfirmed).append(entry)
    ctx.evidence.update({"scope": scope, "pass1": first, "pass2": second,
                         "services": confirmed, "unconfirmed": unconfirmed})

    def label(e, names=None):
        name = (names or {}).get(e["port"]) or e["service"] or "unknown"
        return f"{e['ip']}:{e['port']} ({name})"

    results = []
    risky = [e for e in confirmed if e["port"] in HIGH_RISK]
    results.append(result("SVC-01", "fail" if risky else "pass",
                          ("Exposed: " + ", ".join(label(e, HIGH_RISK) for e in risky)) if risky
                          else "No RDP, SMB, Telnet, VNC or similar services exposed.", {"ports": risky}))
    dbs = [e for e in confirmed if e["port"] in DATABASES]
    results.append(result("SVC-02", "fail" if dbs else "pass",
                          ("Exposed: " + ", ".join(label(e, DATABASES) for e in dbs)) if dbs
                          else "No database or cache ports exposed.", {"ports": dbs}))

    per_host = {}
    for e in confirmed:
        if e["port"] not in WEB_DEFAULT:
            per_host.setdefault(e["ip"], []).append(e["port"])
    most = max((len(v) for v in per_host.values()), default=0)
    status = "pass" if most <= 2 else "partial" if most <= 5 else "fail"
    summary = f"Up to {most} open port(s) besides 80/443 on one address; {len(confirmed)} confirmed in total."
    if unconfirmed:
        summary += f" {len(unconfirmed)} port(s) were open in pass one only: reviewer to confirm."
    results.append(result("SVC-03", status, summary, {"per_host": per_host, "unconfirmed": unconfirmed},
                          review=bool(unconfirmed)))

    mgmt = [e for e in confirmed if e["port"] in MANAGEMENT
            or ("http" in e["service"] and e["port"] not in WEB_DEFAULT)]
    if mgmt:
        results.append(result("SVC-04", "review",
                              "Web services on non-standard ports: " + ", ".join(label(e) for e in mgmt)
                              + ". Screenshots are not taken automatically: reviewer to open them and check for "
                              "admin panels or login pages.", {"ports": mgmt}))
    else:
        results.append(result("SVC-04", "pass", "No management interfaces on non-standard ports."))

    clear = [e for e in confirmed if e["port"] in CLEARTEXT and e.get("tunnel") != "ssl"]
    results.append(result("SVC-05", "fail" if clear else "pass",
                          ("Unencrypted: " + ", ".join(label(e, CLEARTEXT) for e in clear)) if clear
                          else "No unencrypted login protocols exposed.", {"ports": clear}))
    return results
