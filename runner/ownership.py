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
