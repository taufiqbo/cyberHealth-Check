"""Ownership proof: a DNS TXT record or a file on the web server, carrying a per-assessment token."""
import ipaddress
import re
import secrets

from .net import NetError, is_public_ip

TXT_LABEL = "_cyberhealth"
FILE_PATH = "/.well-known/cyberhealth-verify.txt"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def new_token():
    return "chk-" + secrets.token_urlsafe(18)


def normalise_target(raw, allow_private=False):
    """Returns (target, type) or raises ValueError with a message for the user."""
    value = (raw or "").strip().lower()
    value = re.sub(r"^[a-z]+://", "", value).split("/")[0].rstrip(".")
    if not value:
        raise ValueError("Enter a domain or an IP address.")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        if not allow_private and not is_public_ip(value):
            raise ValueError("That IP address is not public; only internet-facing addresses can be checked.")
        return str(ip), "ip"
    if value.startswith("www."):
        value = value[4:]
    if not DOMAIN_RE.match(value):
        raise ValueError("That does not look like a domain name (for example: example.com).")
    return value, "domain"


def instructions(assessment):
    token = assessment["ownership_token"]
    target = assessment["target"]
    steps = []
    if assessment["target_type"] == "domain":
        steps.append({"method": "DNS TXT record",
                      "how": f"Add a TXT record named {TXT_LABEL}.{target} with the value",
                      "value": f"cyberhealth-verify={token}"})
    steps.append({"method": "File on the web server",
                  "how": f"Publish http(s)://{target}{FILE_PATH} containing",
                  "value": token})
    return steps


def check(net, assessment):
    """Returns (verified, method, message)."""
    token = assessment["ownership_token"]
    target = assessment["target"]
    errors = []
    if assessment["target_type"] == "domain":
        for name in (f"{TXT_LABEL}.{target}", target):
            try:
                records = net.resolve(name, "TXT")
            except NetError as exc:
                errors.append(str(exc))
                continue
            if any(r.strip() == f"cyberhealth-verify={token}" for r in records):
                return True, "dns", f"TXT record found at {name}."
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}{FILE_PATH}"
        try:
            resp = net.http("GET", url, max_body=4096)
        except NetError as exc:
            errors.append(str(exc))
            continue
        if resp.status == 200 and token in resp.body:
            return True, "http", f"Token found at {url}."
    message = "Token not found yet."
    if errors:
        message += " (" + "; ".join(errors[:2]) + ")"
    return False, None, message


def parse_known_hosts(text, domain):
    """The client's asset list: one name per line (commas or spaces also fine). '*.sub.example.com' covers every
    name under it. Returns a sorted list or raises ValueError naming entries outside the assessed domain."""
    names, bad = set(), []
    for raw in re.split(r"[\s,;]+", (text or "").strip().lower()):
        name = re.sub(r"^[a-z]+://", "", raw).split("/")[0].rstrip(".")
        if not name:
            continue
        bare = name[2:] if name.startswith("*.") else name
        if (bare == domain or bare.endswith("." + domain)) and (bare == domain or DOMAIN_RE.match(bare)):
            names.add(name)
        else:
            bad.append(raw)
    if bad:
        raise ValueError(f"Not part of {domain}: " + ", ".join(bad[:5]))
    return sorted(names)


def host_is_known(name, known):
    for entry in known:
        if entry.startswith("*."):
            if name.endswith(entry[1:]):
                return True
        elif name == entry:
            return True
    return False
