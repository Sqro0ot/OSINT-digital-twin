# app/greynoise_client.py
"""
GreyNoise Community API client.

Endpoint: GET https://api.greynoise.io/v3/community/{ip}
Docs:     https://docs.greynoise.io/reference/get_v3-community-ip

Free tier: 100 IP/day (no key needed for basic use, but key raises limits).
Set GREYNOISE_API_KEY in .env for higher quotas.
"""

import logging
import time
from typing import Dict, Optional

import httpx

log = logging.getLogger(__name__)

_BASE = "https://api.greynoise.io/v3/community"
_TIMEOUT = 8.0
_RETRY_AFTER = 1.0  # seconds between retries on 429


def _headers(api_key: Optional[str]) -> Dict[str, str]:
    h = {"Accept": "application/json"}
    if api_key:
        h["key"] = api_key
    return h


def lookup_ip(
    ip: str,
    api_key: Optional[str] = None,
    retries: int = 2,
) -> Optional[Dict]:
    """
    Fetch GreyNoise community data for a single IP.

    Returns dict with fields:
      ip, noise, riot, classification, name, link, last_seen, message
    Returns None on error or if IP not in GreyNoise dataset.
    """
    url = f"{_BASE}/{ip}"
    for attempt in range(retries + 1):
        try:
            resp = httpx.get(url, headers=_headers(api_key), timeout=_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                # IP not found in GreyNoise — not necessarily bad, just unknown
                return {"ip": ip, "noise": False, "riot": False,
                        "classification": "unknown", "message": "not_found"}
            if resp.status_code == 429:
                log.warning("GreyNoise rate limit hit for %s, waiting %.1fs", ip, _RETRY_AFTER)
                time.sleep(_RETRY_AFTER)
                continue
            log.warning("GreyNoise returned %s for %s", resp.status_code, ip)
            return None
        except httpx.TimeoutException:
            log.warning("GreyNoise timeout for %s (attempt %d)", ip, attempt + 1)
        except Exception as exc:
            log.error("GreyNoise error for %s: %s", ip, exc)
            return None
    return None


def bulk_lookup(
    ips: list[str],
    api_key: Optional[str] = None,
    delay: float = 0.12,
) -> Dict[str, Dict]:
    """
    Lookup multiple IPs, respecting rate limits.
    Returns dict: ip -> greynoise_result

    delay=0.12s → ~8 req/s → stays well within 100/day free tier when used sparingly.
    For larger batches, increase delay or add daily quota tracking.
    """
    results: Dict[str, Dict] = {}
    for ip in ips:
        result = lookup_ip(ip, api_key=api_key)
        if result is not None:
            results[ip] = result
        if delay > 0:
            time.sleep(delay)
    return results


def parse_classification(gn_data: Optional[Dict]) -> str:
    """
    Returns: 'malicious' | 'benign' | 'unknown'
    Adds 'noise' prefix if the IP is a known internet scanner.
    """
    if not gn_data:
        return "unknown"
    if gn_data.get("riot"):
        return "benign"  # known CDN/cloud — definitely legit
    classification = gn_data.get("classification", "unknown") or "unknown"
    if gn_data.get("noise") and classification != "malicious":
        return "noise"   # active scanner but not classified as malicious
    return classification


def extract_tags(gn_data: Optional[Dict]) -> list[str]:
    """Extract threat tags if present (only available on paid tiers)."""
    if not gn_data:
        return []
    return gn_data.get("tags") or []
