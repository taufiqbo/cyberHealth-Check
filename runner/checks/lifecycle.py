"""LCY-01..03: compares versions already collected (web banners, Nmap) with end-of-life data.
Sends no traffic to the target."""
from .. import eol
from . import result


def _judge_all(found, data):
    seen, judged = set(), []
    for item in found:
        key = (item["product_key"], item["version"])
        if key in seen:
            continue
        seen.add(key)
        verdict = eol.judge(item["product_key"], item["version"], data)
        verdict["where"] = item["where"]
        judged.append(verdict)
    return judged


def _verdict(control_id, judged, what, no_data_text):
    if not judged:
        return result(control_id, "info", no_data_text)
    known = [j for j in judged if j["status"] != "unknown"]
    dead = [j for j in judged if j["status"] == "eol"]
    detail = {"software": judged}
    if dead:
        return result(control_id, "fail", "End-of-life: " + ", ".join(
            f"{j['product']} {j['version']} ({j['where']}, ended {j['eol'] or 'already'})" for j in dead[:5]), detail)
    if not known:
        return result(control_id, "info", f"{what} versions seen but no lifecycle data for them.", detail)
    return result(control_id, "pass", "Supported: " + ", ".join(f"{j['product']} {j['version']}" for j in known[:6]),
                  detail)


def run(ctx):
    data, source = eol.load(ctx.net, ctx.config.cache_dir)
    web = ctx.prior.get("web") or {}
    services = ctx.prior.get("services")

    web_found = []
    for banner in web.get("banners", []):
        for product, version in eol.from_banner(banner["value"]):
            web_found.append({"product_key": product, "version": version,
                              "where": f"{banner['host']} {banner['header']} header"})
    svc_found = []
    for svc in (services or {}).get("services", []):
        hit = eol.from_nmap(svc.get("product"), svc.get("version"))
        if hit:
            svc_found.append({"product_key": hit[0], "version": hit[1], "where": f"{svc['ip']}:{svc['port']}"})
        for product, version in eol.from_banner(svc.get("version", "")):
            svc_found.append({"product_key": product, "version": version, "where": f"{svc['ip']}:{svc['port']}"})

    web_judged = _judge_all(web_found, data)
    svc_judged = _judge_all(svc_found, data)
    ctx.evidence.update({"eol_source": source, "web": web_judged, "services": svc_judged})
    results = []
    if not web:
        results.append(result("LCY-01", "not_tested", "Waiting for the Web module."))
    else:
        results.append(_verdict("LCY-01", web_judged, "Web software",
                                "No software versions disclosed in web headers, so lifecycle cannot be "
                                "judged from outside."))
    if services is None:
        results.append(result("LCY-02", "not_tested", "Waiting for the Services module (Nmap)."))
    else:
        results.append(_verdict("LCY-02", svc_judged, "Service",
                                "Nmap could not read any service versions."))
    everything = web_judged + svc_judged
    soon = [j for j in everything if j["status"] == "soon"]
    if soon:
        results.append(result("LCY-03", "partial", "Reaching end-of-life within 6 months: " + ", ".join(
            f"{j['product']} {j['version']} on {j['eol']}" for j in soon), {"software": soon}))
    elif any(j["status"] != "unknown" for j in everything):
        results.append(result("LCY-03", "pass", "Nothing reaches end-of-life in the next 6 months."))
    else:
        results.append(result("LCY-03", "info", "No versioned software to plan for."))
    return results
