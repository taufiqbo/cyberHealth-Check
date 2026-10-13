"""Check modules. Each module exposes run(ctx) and returns one result per control it owns."""
from dataclasses import dataclass, field

from ..controls import for_module


@dataclass
class Context:
    assessment: dict
    net: object
    config: object
    prior: dict = field(default_factory=dict)     # module -> evidence of its latest good run
    evidence: dict = field(default_factory=dict)  # this run's raw observations
    report_path: str = ""
    on_progress: object = None  # callable(message), set by the worker

    def progress(self, message):
        if self.on_progress:
            self.on_progress(message)

    @property
    def target(self):
        return self.assessment["target"]

    @property
    def is_ip(self):
        return self.assessment["target_type"] == "ip"

    def web_hosts(self):
        disc = self.prior.get("discovery") or {}
        hosts = disc.get("web_hosts")
        if hosts:
            return hosts
        if self.is_ip:
            return [self.target]
        return [self.target, f"www.{self.target}"]

    def primary_host(self):
        disc = self.prior.get("discovery") or {}
        return disc.get("primary_host") or self.target


def result(control_id, status, summary, details=None, review=False):
    return {
        "control_id": control_id,
        "status": status,
        "summary": summary,
        "details": details or {},
        "review": review or status in ("review", "inconclusive"),
    }


def all_status(module, status, summary):
    return [result(c.id, status, summary) for c in for_module(module)]


def worst(statuses):
    order = ["fail", "inconclusive", "partial", "pass"]
    for s in order:
        if s in statuses:
            return s
    return "na"


def _registry():
    from . import brand, discovery, email, lifecycle, services, tls, vulns, web
    return {
        "discovery": discovery.run,
        "tls": tls.run,
        "email": email.run,
        "web": web.run,
        "brand": brand.run,
        "services": services.run,
        "lifecycle": lifecycle.run,
        "vulns": vulns.run,
    }


def get_runner(module):
    return _registry()[module]
