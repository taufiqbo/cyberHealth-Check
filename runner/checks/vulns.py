"""VUL-01..04: imports a Greenbone/OpenVAS XML report and enriches it with CISA KEV and NVD.
Greenbone itself is not launched by this system."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import DefusedXmlException, ElementTree

from ..net import NetError
from . import all_status, result

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
MIN_QOD = 70  # Greenbone's own default quality-of-detection filter
OLD_DAYS = 365


def parse_greenbone(xml_text):
    root = ElementTree.fromstring(xml_text)
    findings, seen = [], set()
    for res in root.iter("result"):
        nvt = res.find("nvt")
        if nvt is None:
            continue
        try:
            severity = float(res.findtext("severity") or nvt.findtext("cvss_base") or 0)
        except ValueError:
            severity = 0.0
        if severity <= 0:
            continue  # log-level results
        qod_text = res.findtext("qod/value")
        if qod_text and qod_text.isdigit() and int(qod_text) < MIN_QOD:
            continue
        host_el = res.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        port = (res.findtext("port") or "").strip()
        oid = nvt.get("oid", "")
        key = (host, port, oid)
        if key in seen:
            continue
        seen.add(key)
        cves = [ref.get("id") for ref in nvt.iter("ref") if (ref.get("type") or "").lower() == "cve"]
        legacy = nvt.findtext("cve") or ""
        cves += [c.strip() for c in legacy.split(",") if c.strip().upper().startswith("CVE-")]
        findings.append({
            "name": (res.findtext("name") or nvt.findtext("name") or "").strip(),
            "host": host,
            "port": port,
            "oid": oid,
            "severity": severity,
            "threat": res.findtext("threat") or "",
            "cves": sorted(set(cves)),
        })
    return findings


def _load_kev(ctx):
    cache = Path(ctx.config.cache_dir) / "kev.json"
    if not ctx.net.demo:
        fresh = cache.exists() and time.time() - cache.stat().st_mtime < 24 * 3600
        if not fresh:
            try:
                data = ctx.net.get_json(KEV_URL, timeout=60)
                cache.write_text(json.dumps(data))
            except NetError:
                pass
        if cache.exists():
            data = json.loads(cache.read_text())
            return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("catalogVersion")
        return None, None
    data = ctx.net.get_json(KEV_URL)
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}, data.get("catalogVersion")


def _nvd_published(ctx, cves):
    cache_file = Path(ctx.config.cache_dir) / "nvd.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    headers = {"apiKey": ctx.config.nvd_api_key} if ctx.config.nvd_api_key else {}
    budget = 50 if ctx.config.nvd_api_key else 20
    pause = 0.7 if ctx.config.nvd_api_key else 6.5  # NVD public rate limits
    for cve in cves:
        if cve in cache or budget <= 0:
            continue
        budget -= 1
        try:
            data = ctx.net.get_json(NVD_URL.format(cve), headers=headers, timeout=30)
            vulns = data.get("vulnerabilities", [])
            cache[cve] = vulns[0]["cve"].get("published") if vulns else None
        except NetError:
            break
        if not ctx.net.demo:
            time.sleep(pause)
    if not ctx.net.demo:
        cache_file.write_text(json.dumps(cache))
    return {c: cache.get(c) for c in cves}


def run(ctx):
    path = ctx.report_path
    if not path or not Path(path).exists():
        return all_status("vulns", "not_tested", "No Greenbone report uploaded yet.")
    try:
        findings = parse_greenbone(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (ElementTree.ParseError, DefusedXmlException, ValueError) as exc:
        return all_status("vulns", "inconclusive", f"The uploaded report could not be read: {exc}")
    scope = set(ctx.assessment.get("headsup_scope_list", []))
    outside = sorted({f["host"] for f in findings if scope and f["host"] not in scope})
    ctx.progress("loading the CISA KEV catalogue")
    kev, kev_version = _load_kev(ctx)
    all_cves = sorted({c for f in findings for c in f["cves"]})
    ctx.progress("looking up CVE dates in NVD (slow without an API key)")
    published = _nvd_published(ctx, [c for f in findings if f["severity"] >= 4.0 for c in f["cves"]])
    ctx.evidence.update({"findings": findings, "kev_catalog": kev_version, "nvd_published": published,
                         "hosts_outside_scope": outside})

    def line(f):
        cves = f" [{', '.join(f['cves'][:3])}]" if f["cves"] else ""
        return f"{f['host']} {f['port']}: {f['name']} ({f['severity']}){cves}"

    results = []
    critical = [f for f in findings if f["severity"] >= 9.0]
    note = (f" Report also covers {len(outside)} address(es) outside the confirmed scope: reviewer to check."
            if outside else "")
    results.append(result("VUL-01", "fail" if critical else "pass",
                          ((f"{len(critical)} critical finding(s): " + "; ".join(map(line, critical[:3])) + ".")
                           if critical else f"No critical findings in {len(findings)} result(s).") + note,
                          {"findings": critical, "hosts_outside_scope": outside}, review=bool(outside)))
    high = [f for f in findings if 7.0 <= f["severity"] < 9.0]
    status = "pass" if not high else "partial" if len(high) <= 2 else "fail"
    results.append(result("VUL-02", status,
                          (f"{len(high)} high finding(s): " + "; ".join(map(line, high[:3]))) if high
                          else "No high findings.", {"findings": high}))
    if kev is None:
        results.append(result("VUL-03", "inconclusive", "CISA KEV catalogue could not be downloaded."))
    else:
        hits = [f for f in findings if any(c in kev for c in f["cves"])]
        kev_cves = sorted({c for f in hits for c in f["cves"] if c in kev})
        results.append(result("VUL-03", "fail" if hits else "pass",
                              (f"Known exploited: {', '.join(kev_cves[:6])}") if hits
                              else f"None of {len(all_cves)} CVE(s) are in the CISA KEV catalogue.",
                              {"kev": [{"cve": c, "name": kev[c].get("vulnerabilityName"),
                                        "due": kev[c].get("dueDate")} for c in kev_cves],
                               "catalog": kev_version}))
    now = datetime.now(timezone.utc)
    dated = {c: p for c, p in published.items() if p}
    old = []
    for f in findings:
        if f["severity"] < 4.0:
            continue
        ages = [(now - datetime.fromisoformat(dated[c]).replace(tzinfo=timezone.utc)).days
                for c in f["cves"] if c in dated]
        if ages and max(ages) > OLD_DAYS:
            old.append({**f, "age_days": max(ages)})
    undated = [c for c in published if not published[c]]
    if old:
        status = "partial" if len(old) <= 3 else "fail"
        results.append(result("VUL-04", status,
                              f"{len(old)} finding(s) with CVEs published over a year ago.", {"findings": old}))
    elif published and len(undated) == len(published):
        results.append(result("VUL-04", "inconclusive", "CVE dates could not be read from NVD."))
    else:
        results.append(result("VUL-04", "pass", "No findings with CVEs older than a year."))
    return results
