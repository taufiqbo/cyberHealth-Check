"""The External CyberHealth Check control catalogue."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    id: str
    module: str
    title: str
    severity: str  # critical | high | medium | low
    why: str
    fix: str
    manual: bool = False  # always needs a human (screenshots)


MODULES = {
    "discovery": "Discovery",
    "tls": "TLS",
    "email": "Email",
    "web": "Web",
    "brand": "Brand",
    "services": "Services",
    "lifecycle": "Lifecycle",
    "vulns": "Vulnerabilities",
}

_C = Control
CONTROLS = [
    # Discovery
    _C("EAS-01", "discovery", "Internet-facing assets are known", "medium",
       "You cannot protect hosts you do not know about. Certificate logs and DNS show what the internet can see.",
       "Keep an inventory of every public hostname and retire the ones no longer used."),
    _C("EAS-02", "discovery", "No dangling DNS records (subdomain takeover)", "high",
       "A DNS record pointing to a deleted cloud resource can be claimed by someone else and used to serve content under your name.",
       "Remove CNAME records that point to cloud services you no longer use."),
    _C("EAS-03", "discovery", "No test, staging or admin hostnames exposed", "medium",
       "Development and admin systems are often less protected than production.",
       "Put non-production and admin systems behind a VPN or an allow-list."),
    _C("EAS-04", "discovery", "DNSSEC is enabled", "low",
       "DNSSEC stops attackers forging DNS answers for your domain.",
       "Enable DNSSEC at your DNS host and publish the DS record at your registrar."),
    _C("EAS-05", "discovery", "Name servers are redundant and refuse zone transfers", "medium",
       "One name server is a single point of failure; open zone transfers hand out your whole DNS map.",
       "Use at least two name servers and allow zone transfers only to your own secondaries."),
    # TLS
    _C("TLS-01", "tls", "HTTPS is available", "high",
       "Without HTTPS, anything sent to the site can be read or changed in transit.",
       "Serve every public site over HTTPS."),
    _C("TLS-02", "tls", "Certificate is trusted", "high",
       "Browsers warn visitors about untrusted certificates, which teaches people to click through warnings.",
       "Use a certificate from a public CA and serve the full chain."),
    _C("TLS-03", "tls", "Certificate is not close to expiry", "medium",
       "An expired certificate takes the site offline for most visitors.",
       "Automate renewal (for example with ACME) and monitor expiry dates."),
    _C("TLS-04", "tls", "Certificate matches the host name", "high",
       "A name mismatch shows a security warning and may mean the wrong site is being served.",
       "Issue certificates that cover every host name in use."),
    _C("TLS-05", "tls", "Old protocols (TLS 1.0 / 1.1) are disabled", "medium",
       "TLS 1.0 and 1.1 have known weaknesses and fail PCI DSS and most baselines.",
       "Allow TLS 1.2 and TLS 1.3 only."),
    _C("TLS-06", "tls", "Weak ciphers are disabled", "medium",
       "RC4, 3DES, NULL and anonymous ciphers can be broken or give no protection at all.",
       "Use a modern cipher list such as Mozilla's 'intermediate' profile."),
    _C("TLS-07", "tls", "HTTP redirects to HTTPS and HSTS is set", "medium",
       "Without a redirect and HSTS, visitors can be silently downgraded to plain HTTP.",
       "Redirect all HTTP to HTTPS and send Strict-Transport-Security with max-age of at least 180 days."),
    # Email
    _C("EML-01", "email", "SPF record is published", "high",
       "SPF tells receiving mail servers which servers may send email for your domain.",
       "Publish exactly one SPF (v=spf1) TXT record."),
    _C("EML-02", "email", "SPF is strict and valid", "medium",
       "A soft or open SPF policy, or one with more than ten DNS lookups, gives little protection.",
       "End SPF with -all and keep it under ten DNS lookups."),
    _C("EML-03", "email", "DMARC record is published", "high",
       "DMARC tells receivers what to do with mail that fails SPF and DKIM, and sends you reports.",
       "Publish a DMARC record at _dmarc.<your domain>."),
    _C("EML-04", "email", "DMARC is enforced", "high",
       "A DMARC policy of 'none' only monitors; spoofed mail still gets delivered.",
       "Move DMARC to p=quarantine and then p=reject once reports look clean."),
    _C("EML-05", "email", "DKIM signing is set up", "medium",
       "DKIM signs outgoing mail so receivers can tell it really came from you.",
       "Enable DKIM signing on every service that sends mail for your domain."),
    _C("EML-06", "email", "MTA-STS is published", "low",
       "MTA-STS makes other mail servers use encrypted connections when sending to you.",
       "Publish an _mta-sts TXT record and a policy file."),
    _C("EML-07", "email", "TLS reporting (TLS-RPT) is published", "low",
       "TLS-RPT tells you when other servers fail to deliver mail to you securely.",
       "Publish an _smtp._tls TXT record with a reporting address."),
    # Web
    _C("WEB-01", "web", "Content-Security-Policy is set", "medium",
       "A content security policy limits the damage of cross-site scripting.",
       "Send a Content-Security-Policy header without 'unsafe-inline' or 'unsafe-eval' for scripts."),
    _C("WEB-02", "web", "Home page looks legitimate (visual check)", "medium",
       "A reviewer checks the home page for defacement, default pages or error pages.",
       "Remove default pages and make sure error pages show no technical detail.", manual=True),
    _C("WEB-03", "web", "Clickjacking protection is set", "medium",
       "Without it, another site can frame yours and trick users into clicking.",
       "Send X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors."),
    _C("WEB-04", "web", "X-Content-Type-Options is set", "low",
       "Stops browsers guessing file types, which can turn uploads into scripts.",
       "Send X-Content-Type-Options: nosniff."),
    _C("WEB-05", "web", "Referrer-Policy is set", "low",
       "Limits what your URLs reveal to other sites.",
       "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
    _C("WEB-06", "web", "Cookies have security flags", "medium",
       "Cookies without Secure, HttpOnly and SameSite are easier to steal or misuse.",
       "Set Secure, HttpOnly and SameSite on session cookies."),
    _C("WEB-07", "web", "Software versions are not disclosed", "low",
       "Version numbers in headers tell attackers exactly which exploits to try.",
       "Remove version details from Server and X-Powered-By headers."),
    _C("WEB-08", "web", "Permissions-Policy is set", "low",
       "Limits which browser features (camera, microphone, location) pages may use.",
       "Send a Permissions-Policy header that disables features you do not use."),
    # Brand
    _C("BRD-01", "brand", "Lookalike websites checked (visual check)", "medium",
       "A reviewer checks live lookalike domains for copies of your site used for phishing.",
       "Report impersonating sites to the registrar and host; consider a takedown service.", manual=True),
    _C("BRD-02", "brand", "Few lookalike domains are registered", "low",
       "Lookalike domains are used for phishing and fake invoices.",
       "Register the most likely lookalikes yourself and watch for new ones."),
    _C("BRD-03", "brand", "No lookalike domains can receive email", "medium",
       "A lookalike with mail servers can send and receive convincing phishing email.",
       "Investigate these domains and report abuse; warn staff and customers."),
    _C("BRD-04", "brand", "Domain registration is healthy", "medium",
       "An expired or unlocked domain can be lost or hijacked.",
       "Enable auto-renew and registrar transfer lock."),
    # Services
    _C("SVC-01", "services", "No high-risk remote access services exposed", "critical",
       "RDP, SMB, Telnet and VNC on the internet are among the most common ways in for ransomware.",
       "Close these ports and use a VPN with multi-factor authentication."),
    _C("SVC-02", "services", "No databases or caches exposed", "critical",
       "Databases open to the internet are found and attacked within hours.",
       "Allow database ports only from application servers."),
    _C("SVC-03", "services", "Few services are exposed", "medium",
       "Every open port is something that must be patched and watched.",
       "Close ports that do not need to be public."),
    _C("SVC-04", "services", "Management interfaces checked (visual check)", "high",
       "A reviewer checks admin panels and login pages found on non-standard ports.",
       "Put management interfaces behind a VPN or allow-list.", manual=True),
    _C("SVC-05", "services", "No unencrypted services exposed", "high",
       "FTP, Telnet, POP3, IMAP and LDAP without TLS send passwords in clear text.",
       "Switch to the encrypted versions (SFTP, IMAPS, LDAPS) and close the old ports."),
    # Lifecycle
    _C("LCY-01", "lifecycle", "Web software is supported", "high",
       "End-of-life software gets no security fixes.",
       "Upgrade to a supported version."),
    _C("LCY-02", "lifecycle", "Network service software is supported", "high",
       "End-of-life software gets no security fixes.",
       "Upgrade to a supported version."),
    _C("LCY-03", "lifecycle", "Nothing reaches end-of-life in the next 6 months", "low",
       "Planning upgrades early avoids running unsupported software.",
       "Plan upgrades for the listed software."),
    # Vulnerabilities
    _C("VUL-01", "vulns", "No critical vulnerabilities", "critical",
       "Critical vulnerabilities (CVSS 9.0 or higher) are often exploitable remotely without a login.",
       "Patch or mitigate within 7 days."),
    _C("VUL-02", "vulns", "No high vulnerabilities", "high",
       "High vulnerabilities (CVSS 7.0 to 8.9) are serious and should be fixed quickly.",
       "Patch or mitigate within 30 days."),
    _C("VUL-03", "vulns", "No known exploited vulnerabilities (CISA KEV)", "critical",
       "These vulnerabilities are being used by attackers right now.",
       "Patch immediately; treat as an incident if the system may already be compromised."),
    _C("VUL-04", "vulns", "No old unpatched vulnerabilities", "medium",
       "Vulnerabilities published more than a year ago point to a patching gap.",
       "Review the patch process for the affected systems."),
    _C("VUL-05", "web", "A vulnerability disclosure contact is published (security.txt)", "low",
       "security.txt tells researchers how to report problems to you.",
       "Publish /.well-known/security.txt with Contact and Expires fields (RFC 9116)."),
]

BY_ID = {c.id: c for c in CONTROLS}


def for_module(module):
    return [c for c in CONTROLS if c.module == module]


STATUS_LABELS = {
    "pass": "Pass",
    "partial": "Partial",
    "fail": "Fail",
    "review": "Needs review",
    "inconclusive": "Inconclusive",
    "info": "Information",
    "na": "Not applicable",
    "not_tested": "Not tested",
}
SCORED = {"pass", "partial", "fail"}
REVIEWER_CHOICES = ["pass", "partial", "fail", "na", "info"]
