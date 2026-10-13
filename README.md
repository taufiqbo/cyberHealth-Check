# CyberHealth Runner

Enter a domain or IP. The system proves ownership, runs the External CyberHealth Check on its own, scores it with CyberHealth Score v1.0, holds the result for human review, and sends a notification. It is an outside-in check, not a penetration test.

## Try it now (demo mode, no network, fictional client)
    pip install -r requirements.txt
    ./run_demo.sh            # then open http://localhost:8000
Logins: admin `admin@demo.example` / `demo-admin`, analyst `analyst@demo.example` / `demo-analyst`, reviewer `reviewer@demo.example` / `demo-reviewer`, client `client@client-example.com` / `demo-client`.

The demo starts clean each time with two assessments of the fictional `client-example.com`:
#1 is fully run (including Nmap and a sample Greenbone report), reviewed and signed off, so the client can see its report;
#2 has the automatic modules done and is waiting for the reviewer. As the analyst you can confirm the provider heads-up
and upload `demo/greenbone-sample.xml` on #2. Only `client-example.com` proves ownership by itself in the demo;
any other domain needs a manually recorded proof, and then most checks come back Inconclusive because there is no network.

## Put it live (IT team)
1. A server with the static IP. Open ports 80/443 inbound; allow outbound DNS, HTTP(S) and the ports Nmap needs.
2. `cp .env.example .env`, edit it, then `docker compose up -d --build`.
3. Browse to your RUNNER_HOST and sign in with RUNNER_ADMIN_EMAIL / PASSWORD. Add people under Team and clients.
4. Optional tools: dnstwist outside Docker: `pip install dnstwist` (found through Python even when its folder is not on PATH). Amass (`docker compose build --build-arg AMASS_VERSION=v4.2.0`, or install the binary on the image; used automatically if found). dnstwist and Nmap are already in the image.
5. Tell the hosting providers the scan IP address. Backups: copy the `runner-data` volume (database and evidence).

Run the tests: `python3 -m pytest -q test_app.py`.

## How an assessment flows
1. **Analyst** creates it (client + domain or IP). The page shows a token.
2. **Ownership**: the client publishes the token as a TXT record at `_cyberhealth.<domain>` (value `cyberhealth-verify=<token>`)
   or as a file at `/.well-known/cyberhealth-verify.txt`. The system re-checks every 10 minutes for 14 days.
   The analyst can instead record other proof (signed letter, registrar email) with a written note.
3. The automatic modules run: Discovery, TLS, Email, Web, Brand, then Lifecycle.
4. Services (Nmap) waits until the analyst confirms the provider heads-up for the listed addresses.
   Vulnerabilities waits for the written provider approval and the uploaded Greenbone/OpenVAS XML report.
5. When nothing is queued the assessment goes **In review** and reviewers are notified.
   Screenshots-type controls and anything Inconclusive are flagged; sign-off is blocked until each has a decision.
6. **Reviewer** signs off. The score is frozen, the client and the analyst are notified, and the assessment is locked.

Every module run writes an evidence file (raw observations + results) and its SHA-256 is kept with the run.
Every action goes into an append-only, hash-chained audit trail.

## What runs and what waits
| Module | Controls | How | Needs |
|---|---|---|---|
| Discovery | EAS-01..05 | crt.sh / CertSpotter, Amass, DNS | ownership proof |
| TLS | TLS-01..07 | handshakes, HTTP HEAD | ownership proof |
| Email | EML-01..07 | DNS TXT | ownership proof |
| Web | WEB-01..08, VUL-05 | HTTP GET of home pages, security.txt | ownership proof |
| Brand | BRD-01..04 | dnstwist, RDAP (WHOIS where the registry has no RDAP, e.g. .my) | ownership proof |
| Services | SVC-01..05 | Nmap twice | ownership proof + provider heads-up confirmed |
| Lifecycle | LCY-01..03 | banners and Nmap versions vs end-of-life data | none |
| Vulnerabilities | VUL-01..04 | Greenbone/OpenVAS XML report import, CISA KEV, NVD | ownership proof + written provider approval and the report |

Nmap runs twice: pass one (`-sT --top-ports 1000`) finds open ports, pass two (`-sV`) re-checks only those and reads versions.
Only ports open in both passes count; ports seen once are listed for the reviewer.
The scoring method is in [SCORING.md](SCORING.md); the controls are in `runner/controls.py`.

## Known limits (be honest with clients)
- Greenbone is imported from its XML report, not launched by this system yet.
- Screenshots (SVC-04, WEB-02, BRD-01) are not taken automatically; those controls go to a human reviewer.
- The weak-cipher and old-protocol probes depend on the server's OpenSSL; when it cannot test, the control is marked Inconclusive and goes to review (confirm with Nmap). On a standard OpenSSL 3 build RC4 and 3DES cannot be offered at all, so TLS-06 usually needs that confirmation.
- DKIM selectors cannot be listed from outside; only common selectors are tried, otherwise EML-05 goes to review.
- End-of-life data covers PHP, nginx, Apache httpd, OpenSSL, IIS, MySQL, PostgreSQL and Tomcat (bundled snapshot, refreshed from endoflife.date when reachable). Other software, such as OpenSSH, is listed without a verdict.
- Live scans against real hosts were not run during development: the build environment had no internet. Test on bintara.com.my first.

## Roles
- **Admin** adds people and clients, reads the audit trail and notifications. Does not run or sign off assessments.
- **Analyst** creates assessments, records ownership and the provider approvals, uploads reports, re-runs modules.
- **Reviewer** changes flagged results (a written note is required) and signs off. A reviewer cannot sign off an assessment they ran or approved while another reviewer exists. If the reviewer is the only one, self sign-off is allowed and written to the audit trail.
- **Client** sees only their own assessments, and results only after sign-off.

The first account created at start-up holds all three staff roles so a one-person team can work.

## Layout
    app.py               web app (Flask): pages, roles, uploads
    runner/pipeline.py   gates, job queue, review and sign-off rules
    runner/checks/       one file per module
    runner/net.py        all network access (demo mode swaps in runner/demo_net.py)
    runner/scoring.py    CyberHealth Score v1.0
    demo/                fictional fixtures (Nmap, dnstwist, Greenbone, KEV)
