# app/whois_client.py
"""
Thin wrapper around ipwhois (RDAP) for IP enrichment.
No API key required. Used in normalize pipeline.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def lookup_ip_whois(ip: str) -> Dict:
    """
    RDAP lookup for a single IP via ipwhois.
    Returns dict with ASN, org, country, CIDR, etc.
    Never raises — returns {"error": ...} on failure.
    """
    if not _is_ip(ip):
        return {"error": f"not_an_ip: {ip}"}

    try:
        from ipwhois import IPWhois
        from ipwhois.exceptions import IPDefinedError, HTTPLookupError
    except ImportError:
        log.warning("ipwhois is not installed — skipping WHOIS enrichment")
        return {"error": "ipwhois_not_installed"}

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
    except Exception as exc:
        log.warning("ipwhois failed for %s: %s", ip, exc)
        return {"error": str(exc)}

    network = result.get("network") or {}
    return {
        "ip": ip,
        "asn": result.get("asn"),
        "asn_description": result.get("asn_description"),
        "asn_country_code": result.get("asn_country_code"),
        "asn_cidr": result.get("asn_cidr"),
        "asn_registry": result.get("asn_registry"),
        "org": network.get("name"),
        "network_cidr": network.get("cidr"),
        "network_type": network.get("type"),
    }


def bulk_whois(
    ips: List[str],
    delay: float = 0.1,
) -> Dict[str, Dict]:
    """
    RDAP lookup for multiple IPs sequentially.
    Returns dict: ip -> whois_result.
    """
    import time

    results: Dict[str, Dict] = {}
    for ip in ips:
        results[ip] = lookup_ip_whois(ip)
        if delay > 0:
            time.sleep(delay)
    return results


def parse_whois_country(whois_data: Optional[Dict]) -> Optional[str]:
    """Extract ISO country code from whois result."""
    if not whois_data:
        return None
    return whois_data.get("asn_country_code") or None


def parse_whois_org(whois_data: Optional[Dict]) -> Optional[str]:
    """Extract org/ISP name from whois result."""
    if not whois_data:
        return None
    return (
        whois_data.get("asn_description")
        or whois_data.get("org")
        or None
    )
