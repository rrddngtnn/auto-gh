"""dns_doctor.py — Zero-dependency read-only DNS legitimacy & cross-domain correlation auditor via DoH JSON."""
from __future__ import annotations

from collections import defaultdict
import os
import re
from typing import Callable
import requests

from .bundle import load_dotenv_file

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
FORWARD_EMAIL_RX = re.compile(r"forward-email=([^\s\"']+)", re.IGNORECASE)

ResolverFn = Callable[[str, str], list[str]]


def doh_resolve(qname: str, rtype: str, timeout: int = 10) -> list[str]:
    """Query Cloudflare DNS-over-HTTPS JSON endpoint for record values."""
    r = requests.get(
        DOH_ENDPOINT,
        params={"name": qname.rstrip("."), "type": rtype.upper()},
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    answers = data.get("Answer") or []
    out: list[str] = []
    for ans in answers:
        val = str(ans.get("data") or "").strip().strip('"')
        if val:
            out.append(val)
    return out


def audit_domain(fqdn: str, resolver: ResolverFn = doh_resolve) -> dict:
    """Evaluate a single domain's A, MX, SPF, DMARC, and public TXT forwarding exposure."""
    domain = fqdn.strip().lower().rstrip(".")
    a_records = resolver(domain, "A")
    mx_records = resolver(domain, "MX")
    txt_records = resolver(domain, "TXT")
    dmarc_records = resolver(f"_dmarc.{domain}", "TXT")

    has_a = len(a_records) > 0
    has_mx = len(mx_records) > 0
    has_spf = any("v=spf1" in t.lower() for t in txt_records)
    has_dmarc = any("v=dmarc1" in t.lower() for t in dmarc_records)

    forward_targets: list[str] = []
    for t in txt_records:
        for m in FORWARD_EMAIL_RX.finditer(t):
            forward_targets.append(m.group(1).lower())

    score = 0
    warnings: list[str] = []

    if has_a:
        score += 25
    else:
        warnings.append("missing_a_record")

    if has_mx:
        score += 25
    else:
        warnings.append("missing_mx_record")

    if has_spf:
        score += 25
    else:
        warnings.append("missing_spf_record")

    if has_dmarc:
        score += 25
    else:
        warnings.append("missing_dmarc_record")

    if forward_targets:
        warnings.append("public_txt_forward_target_exposed")

    return {
        "fqdn": domain,
        "score": score,
        "has_a": has_a,
        "has_mx": has_mx,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "a_records": a_records,
        "mx_records": mx_records,
        "forward_targets": forward_targets,
        "warnings": warnings,
    }


def audit_domain_pool(
    domains: list[str] | None = None,
    resolver: ResolverFn = doh_resolve,
) -> dict:
    """Audit a pool of domains and detect cross-domain forwarding target correlation."""
    load_dotenv_file()
    if domains is None:
        raw = os.environ.get("CATCHALL_DOMAINS", "alpha.example.test,beta.example.test")
        domains = [d.strip() for d in raw.split(",") if d.strip()]

    results = [audit_domain(d, resolver=resolver) for d in domains]
    target_map: dict[str, list[str]] = defaultdict(list)
    for r in results:
        for tgt in r["forward_targets"]:
            target_map[tgt].append(r["fqdn"])

    shared_targets = {tgt: doms for tgt, doms in target_map.items() if len(doms) > 1}
    if shared_targets:
        correlated_set = {d for doms in shared_targets.values() for d in doms}
        for r in results:
            if r["fqdn"] in correlated_set:
                r["score"] = max(0, r["score"] - 30)
                if "cross_domain_shared_forward_target" not in r["warnings"]:
                    r["warnings"].append("cross_domain_shared_forward_target")

    avg_score = round(sum(r["score"] for r in results) / len(results), 1) if results else 0.0
    return {
        "domain_count": len(results),
        "average_score": avg_score,
        "shared_forward_targets": shared_targets,
        "domains": results,
    }
