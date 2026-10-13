# CyberHealth engine brief: features to add to the BINTARA CyberHealth platform

**For:** the BINTARA CyberHealth platform team
**From:** the CyberHealth Runner project (reference implementation in this repository)
**Purpose:** keep the platform's design, organisations, scheduling, PDFs and BM/EN, and add six engine features that make the results more trustworthy. Each section says *why*, the *exact rules*, *what to store*, *what to show*, and *how to test it*. The working code for each rule is referenced so you can read it.

Priority order: 1 → 6. Features 1 and 2 matter most: they protect BINTARA legally and protect clients from unreviewed results.

---

## 1. Ownership proof before any check

**Why.** We must never scan a domain we are not authorised to test. Today the platform starts checks as soon as a domain is assigned.

**Rules**
1. When a domain is added, generate a random token (at least 18 random bytes, URL-safe), e.g. `chk-3xYb…`.
2. The domain is **proven** when either:
   - DNS TXT record at `_cyberhealth.<domain>` has the exact value `cyberhealth-verify=<token>`, or
   - `https://<domain>/.well-known/cyberhealth-verify.txt` (then `http://`) returns 200 and contains the token.
3. Re-check automatically every 10 minutes for 14 days; also a "Check now" button.
4. Alternative: a Global Admin records **manual proof** (signed letter, registrar email). A written note is required; an attachment is optional. This is written to the activity log.
5. Until proven, **no module may contact the domain**. Only the ownership check itself runs.
6. Proof is per domain. Keep it until the domain is removed; re-prove if the client changes.

**Store:** token, method (dns / http / manual), proven_at, proven_by, note, attachment, last_check_at, last_check_result.
**Show:** on the domain page, the two instructions with copyable values, last check time and result, and a clear "Proven" state.
**Test:** a new domain must show "Waiting for ownership proof" and must not appear in any scan log; publishing the TXT value proves it within one check; a wrong token does not.

Reference: `runner/ownership.py`, `runner/pipeline.py` (`check_ownership`, `record_manual_ownership`, `gate`).

---

## 2. Human review and sign-off before the client sees results

**Why.** Automated checks are sometimes wrong (lookalike domains the client owns, screenshots nobody looked at). Clients should only see reviewed results.

**Rules**
1. Every result has a status: Pass, Partial, Fail, **Needs review**, **Inconclusive**, Information, Not applicable, Not tested.
2. A result is **flagged** when its status is Needs review or Inconclusive, or when the check itself asks for review (for example, lookalikes that can receive email, or ports seen in only one scan pass).
3. A **Reviewer** decides each flagged result: Pass / Partial / Fail / Not applicable / Information. **Changing a result requires a written note.** Keep the original status next to the decision.
4. **Sign-off** is blocked while any flag is open.
5. Separation of duties: a reviewer who ran or approved any part of the assessment cannot sign it off **while another reviewer exists**. If they are the only reviewer, self sign-off is allowed and marked as such in the activity log.
6. At sign-off: freeze the score, lock the assessment (no re-runs, no edits), notify the client.
7. **Customer users see an assessment's results only after sign-off.** Before that they see "Your report is being prepared".
8. Weekly automatic assessments follow the same rule: the new snapshot stays internal until signed off. The client keeps seeing the last signed-off snapshot.

**Store:** per result: original_status, status, needs_review, reviewed_by, reviewed_at, review_note. Per assessment: signed_off_at, signed_off_by, self_signoff, frozen score.
**Show:** a "Flagged for review" counter, a review control on each flagged row, a sign-off button that explains why it is disabled.
**Test:** customer login cannot see results of an unsigned assessment (page and PDF); a status change without a note is refused; sign-off with an open flag is refused.

Reference: `runner/pipeline.py` (`review_result`, `signoff_check`, `sign_off`), `app.py` (`report_data`).

---

## 3. Better discovery, with the client's own asset list

**Why.** In a recent run the platform found only 1 host for a client domain; one free source (crt.sh) is often down, and HackerTarget cannot be used commercially without permission.

**Rules**
1. Sources, in this order, merged and de-duplicated:
   - crt.sh (`https://crt.sh/?q=%.<domain>&output=json`), allow 90 s **total**;
   - if it fails: CertSpotter API (`https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names`);
   - subfinder (`subfinder -d <domain> -silent`) and/or Amass (`amass enum -passive -d <domain>`), if installed;
   - a short list of common names (www, mail, vpn, dev, admin, …), kept **only if they resolve**.
2. Resolve every name (CNAME, A, AAAA). "Live" means it has an address.
3. **Client asset list:** each domain can have a list of host names the client says it owns (one per line; `*.sub.example.com` covers everything under it).
4. EAS-01 result:
   - no list given → **Needs review** ("confirm these names with the client");
   - every live name is on the list → **Pass**;
   - 1–2 live names not on the list → **Partial**, flagged; 3 or more → **Fail**, flagged.
   - If every discovery source failed, say so in the result (the list may be incomplete).
5. Dangling DNS (EAS-02): a CNAME whose target no longer exists, or that points to a takeover-prone cloud service (S3, Azure Websites, Heroku, GitHub Pages, …) and does not resolve → **Fail**.

**Show:** "Assets" count, the live list, names not on the client's list highlighted, and which sources succeeded or failed.
**Test:** with crt.sh blocked, CertSpotter still yields names; a live name missing from the client list produces a flagged finding.

Reference: `runner/checks/discovery.py`, `runner/net.py` (`ct_names`), `runner/ownership.py` (`parse_known_hosts`).

---

## 4. End-of-life verdicts for observed software

**Why.** The platform shows "PHP 8.0.30 observed" but does not say that PHP 8.0 lost security support on 26 Nov 2023.

**Rules**
1. Read versions from response headers (`Server`, `X-Powered-By`, e.g. `PHP/8.0.30`, `nginx/1.18.0`, `Apache/2.4.41`, `Microsoft-IIS/8.5`) and, if available, from the Nmap service scan.
2. Match the version to its release line (8.0.30 → 8.0) and compare that line's end-of-life date with today, using the endoflife.date API (`https://endoflife.date/api/<product>.json`, cached for 7 days).
3. Past end-of-life → **Fail** (high severity). Ends within 6 months → **Partial**. No version visible → **Information** ("cannot be judged from outside"), not a pass.
4. CVE "candidates" from NVD should stay **out of the score**, as the platform already does. Prefer real findings from a vulnerability scan (feature 5).

**Test:** a site sending `X-Powered-By: PHP/8.0.30` gets a Fail naming PHP 8.0 and its end date.

Reference: `runner/eol.py`, `runner/checks/lifecycle.py`.

---

## 5. Port scan and vulnerability scan behind approvals

**Why.** Port scans and vulnerability scans are active tests. Hosting providers and clients must agree first.

**Rules**
1. **Services (Nmap)** runs only after an analyst confirms a **provider heads-up** with a note (who was told, how, when) and the exact IP list to scan. Scan only those IPs.
2. Run Nmap twice: pass 1 `-sT --top-ports 1000 --open`; pass 2 `-sT -sV --version-light` on the open ports only. Count a port only if it is open in **both** passes; list the others for the reviewer.
3. Findings: RDP/SMB/Telnet/VNC exposed → Fail (critical); database ports (3306, 5432, 1433, 6379, 27017, 9200, …) → Fail (critical); FTP/Telnet/POP3/IMAP/LDAP without TLS → Fail; admin panels on unusual ports → Needs review.
4. **Vulnerabilities** only after **written provider approval** is recorded and a Greenbone/OpenVAS XML report is uploaded. Ignore log-level results and QoD below 70. CVSS ≥ 9 → critical finding; CVE in CISA KEV → Fail and score cap.

Reference: `runner/checks/services.py`, `runner/checks/vulns.py`, `runner/pipeline.py` (`gate`).

---

## 6. Weighted score, evidence and tamper-evident log

**Why.** "2 of 8 controls passed = 25%" treats a missing Permissions-Policy header like an exposed database.

**Rules (CyberHealth Score v1.0)**
1. Weight each control by severity: critical 10, high 6, medium 3, low 1. Pass = 1, Partial = 0.5, Fail = 0. Not applicable / not tested / needs review are left out.
2. Module score = earned ÷ possible. Overall = weighted average of modules (Discovery 10, TLS 15, Email 15, Web 10, Brand 5, Services 20, Lifecycle 10, Vulnerabilities 15).
3. Caps: any CISA-KEV vulnerability → max 49; any failed critical control → max 69.
4. Grade: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below. Show **coverage** (weight scored ÷ weight applicable); below 60 % label the score **provisional**.
5. Evidence: for every module run, save the raw observations and results as a JSON file and store its SHA-256 hash.
6. Activity log: each entry stores the hash of the previous entry, so any edit or deletion breaks the chain; show "chain intact" to Global Admins.

Reference: `SCORING.md`, `runner/scoring.py`, `runner/pipeline.py` (`_write_evidence`), `runner/audit.py`.

---

## Things the platform already does better (keep them)

Organisations, environments and plans; weekly scheduling and history snapshots; PDF and presentation exports; CSV; BM/EN; the visual design. None of the features above should change these.

## How to try the reference implementation

```
python -m pip install -r requirements.txt
set RUNNER_DEMO=1
python app.py
```
Open http://localhost:8000 (logins are on the sign-in page). Demo mode uses a fictional client and sends no network traffic. Tests: `python -m pytest -q test_app.py`.
