# Feedback for the BINTARA CyberHealth platform team

**From:** the CyberHealth Runner project
**About:** the data sources ("APIs") in the platform that are not working as expected, why, and how the Runner code handles the same problem.
**Based on:** the platform's task-status panel, its Attack Surface Discovery panel and a screen recording. We have not seen the platform's source code, so causes marked *likely* should be confirmed in your logs.

The Runner code is attached (`cyberhealth-runner.zip`). Every fix below points to the file and function that already does it, tested (57 automated tests).

---

## Summary

| # | Platform task | What we saw | Likely cause | Fix (Runner reference) |
|---|---|---|---|---|
| 1 | crt.sh discovery | "Source unavailable" / "Unknown" | crt.sh is often overloaded (timeouts, 502/503, slow trickling responses); no fallback | Fallback to CertSpotter + a **total** time limit · `runner/net.py` `ct_names`, `get_json` |
| 2 | HackerTarget Host Search | "Awaiting commercial permission" | Free tier is not licensed for a paid service; it also answers quota errors as plain text with HTTP 200 | Replace with subfinder / Amass (open source, passive) · `runner/checks/discovery.py` |
| 3 | Certificate-log candidates | "Up to 8 candidates receive DNS validation" | Hard cap of 8 | Resolve all candidates (Runner allows 400, 16 in parallel) · `discovery.py` `_lookup` |
| 4 | Asset inventory reconciliation | "Not assessed" | No client asset list to compare with | Store the client's host list; compare; unknown live names become a finding · `runner/ownership.py` `parse_known_hosts`, `host_is_known`; `discovery.py` EAS-01 |
| 5 | DNSSEC | "Unknown" (resolver validation signal) | Relies on the resolver's AD flag, which depends on which resolver is used | Ask for the **DS record** at the parent zone: present = enabled, absent = not · `discovery.py` EAS-04 |
| 6 | Technology & lifecycle | "Exact version unavailable", while the recording shows "PHP 8.0.30 observed" | Version not passed to the lifecycle step, or lifecycle data not matched to the version | Parse `PHP/8.0.30`-style banners, match the release line (8.0), compare with end-of-life dates · `runner/eol.py`, `runner/checks/lifecycle.py` |
| 7 | NVD, KEV & EPSS | "Exact version unavailable"; CVE candidates like CVE-2007-3205 for PHP 8.0.30 | Keyword search on product + version returns old, unrelated CVEs | Don't score CVE guesses; use real scan findings (Greenbone import) and enrich with KEV/NVD · `runner/checks/vulns.py` |
| 8 | Lookalike DNS checks | "Completed with limits · 100/100" | Cap of 100 lookups | Run dnstwist locally (`pip install dnstwist`), no external quota · `runner/checks/brand.py` |
| 9 | (not shown) Registration data | rdap.org returns 404 for `.my` | rdap.org has no `.my` data | Fall back to WHOIS (server found via `whois.iana.org`) · `brand.py` `_registration`, `parse_whois`; `net.py` `whois` |

---

## Details

### 1. crt.sh: "Source unavailable"
- **Why:** crt.sh is a free community service and is frequently overloaded. Typical failures: connection timeout, HTTP 502/503, or a response that trickles slowly so a per-read timeout never fires.
- **Fix:**
  1. Query `https://crt.sh/?q=%25.<domain>&output=json` with a **total** deadline (Runner: 90 seconds), not only a socket timeout.
  2. If it fails, query CertSpotter: `https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names` (check their current free-tier limits and commercial terms).
  3. Clean names: lower-case, strip `*.`, keep only names inside the assessed domain, de-duplicate.
  4. Record which source worked (or why both failed) in the evidence, and say so in the result instead of "Unknown".
- **Reference:** `runner/net.py` → `LiveNet.get_json` (total deadline, size limit), `LiveNet.ct_names` (fallback); `runner/checks/discovery.py` → `_clean`.

### 2. HackerTarget: "Awaiting commercial permission"
- **Why:** the free HackerTarget API is limited and not intended for a commercial service without a paid plan or permission. Note: when the daily quota is exceeded it returns a plain-text message (for example "API count exceeded") with **HTTP 200**, so code that only checks the status code will treat the error text as a host name.
- **Fix:** drop it (or keep it behind a paid key) and use passive open-source collectors run on your own server: **subfinder** (`subfinder -d <domain> -silent`) and/or **Amass** (`amass enum -passive -d <domain>`). Treat their output as candidates and validate in DNS.
- **Reference:** `runner/checks/discovery.py` (Amass and subfinder blocks), `runner/net.py` `tool_argv`, `run`.

### 3. Discovery capped at 8 candidates
- **Why:** a cap of 8 hides most of the attack surface. In our test of bintara.com.my, the Runner found 16 live host names.
- **Fix:** resolve every candidate (CNAME, A, AAAA) with a thread pool and per-lookup timeouts; cap at a few hundred to protect the server, not at 8.
- **Reference:** `runner/checks/discovery.py` → `_lookup`, `MAX_NAMES`.

### 4. Asset inventory reconciliation: "Not assessed"
- **Why:** the platform has no client asset list to compare against. ("Not assessed" is the honest answer here, which is better than a pass.)
- **Fix:** let the analyst store the client's host names (one per line; `*.sub.example.com` covers a subtree). Then:
  - no list → **Needs review** (reviewer confirms the names with the client);
  - every live name on the list → **Pass**;
  - 1–2 live names not on the list → **Partial**, flagged; 3 or more → **Fail**, flagged.
- **Reference:** `runner/ownership.py` → `parse_known_hosts`, `host_is_known`; `runner/checks/discovery.py` EAS-01 block; `runner/pipeline.py` → `set_known_hosts`.

### 5. DNSSEC: "Unknown"
- **Why:** the "resolver validation signal" (AD flag) depends on whether the resolver you query validates DNSSEC. Many do not, so the answer is often unknown.
- **Fix:** query the **DS** record for the zone (`DS bintara.com.my`). A DS record at the parent means DNSSEC is enabled; none means it is not. This gives a definite answer from any resolver.
- **Reference:** `runner/checks/discovery.py` → `_zone_apex` and the EAS-04 block.

### 6. Technology & lifecycle: "Exact version unavailable"
- **Why (likely):** the version is detected (the recording shows "PHP 8.0.30 observed" from the `X-Powered-By` header) but not handed to the lifecycle step, or the lifecycle lookup expects a different format.
- **Fix:** parse banners with simple patterns (`PHP/(\d+\.\d+(\.\d+)?)`, `nginx/…`, `Apache/…`, `Microsoft-IIS/…`, `OpenSSL/…`), map the version to its release line (8.0.30 → 8.0), and compare with end-of-life dates from `https://endoflife.date/api/<product>.json` (cache for a week; keep a bundled snapshot for when it is unreachable). PHP 8.0 reached end of life on 26 Nov 2023, so this should be a **Fail**.
- **Reference:** `runner/eol.py` (`PATTERNS`, `find_cycle`, `judge`, `load`), `runner/checks/lifecycle.py`, snapshot `runner/data/eol.json`.

### 7. NVD, KEV & EPSS: noisy or missing
- **Why:** searching NVD by product name and version (keyword search) returns many CVEs that do not apply (for example a 2007 CVE for PHP 8.0.30). The platform correctly keeps these out of the score, but they confuse clients.
- **Fix options:**
  - Preferred: take vulnerabilities from an actual scan (Greenbone/OpenVAS XML import, with provider approval), then enrich each CVE with CISA KEV (actively exploited?) and NVD (publish date). Runner: `runner/checks/vulns.py` → `parse_greenbone`, `_load_kev`, `_nvd_published`.
  - If you keep version-based lookups: query NVD by CPE (for example `cpe:2.3:a:php:php:8.0.30`) rather than keywords; respect NVD rate limits (much lower without an API key; get a free key); call EPSS in bulk (`https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2`).
- Also check: NVD returns HTTP 403/429 when rate-limited. Treat that as "try later", not "no CVEs".

### 8. Lookalike checks capped at 100
- **Fix:** run **dnstwist** locally: `dnstwist --registered --format json <domain>`. It generates and resolves thousands of permutations itself, with no external quota. On Windows, if `dnstwist` is not on PATH, run it as `python -m dnstwist`.
- **Reference:** `runner/checks/brand.py` → `_lookalikes`; `runner/net.py` → `tool_argv`.

### 9. `.my` registration data
- **Why:** rdap.org returns 404 for `.my` domains.
- **Fix:** if RDAP fails, use WHOIS: ask `whois.iana.org` (port 43) for the TLD's server (`whois.mynic.my`), query it, and parse the expiry date and transfer-lock status. If the registry does not publish lock status, flag it for review rather than failing it.
- **Reference:** `runner/net.py` → `whois`, `_whois_query`; `runner/checks/brand.py` → `parse_whois`, `_registration_result`.

---

## General rules that prevent "not working as expected"

1. **Every external call has a total deadline and a size limit.** One slow source must never stall an assessment. (Runner: `get_json`; each module also has an overall time limit in `runner/pipeline.py` → `_run_with_time_limit`.)
2. **A failed source is "Inconclusive" with the reason, never "Pass" and never silently "Unknown".** If DNS itself fails, all DNS-based results are Inconclusive, not Fail (`pipeline.py`, `DNS_MODULES` guard).
3. **Validate the response body, not just the status code** (quota messages with HTTP 200, HTML error pages where JSON was expected).
4. **Cache public datasets** (KEV daily, end-of-life weekly, NVD per CVE) so a brief outage does not break assessments.
5. **Log each step** so you can see where a run is waiting (Runner prints progress per step and shows it in the UI).
6. **Store raw evidence with a SHA-256 hash** for every run, so any result can be explained later.

See also `docs/ENGINE-BRIEF.md` in the zip for the other features we recommend (ownership proof, reviewer sign-off, weighted scoring, audit trail).
