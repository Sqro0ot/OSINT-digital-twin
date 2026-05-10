# app/greynoise_client.py
"""
GreyNoise Community API client.

Endpoint: GET https://api.greynoise.io/v3/community/{ip}
Docs:     https://docs.greynoise.io/reference/get_v3-community-ip

Free tier with API key: 100 IP/day.
Set GREYNOISE_API_KEY in .env.

Rate limits:
  - No key:  25 req/week  (basically useless)
  - Free account key: 100 req/day
  - Paid: higher limits
"""

import logging
import time
from typing import Dict, List, Optional

import httpx

log = logging.getLogger(__name__)

_BASE = "https://api.greynoise.io/v3/community"
_TIMEOUT = 8.0
_RETRY_WAIT = 2.0


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

    Returns dict on success, None on hard error.
    Returns stub with classification='unknown' on 404 or rate-limit (so pipeline never breaks).
    """
    if not api_key:
        # Without a key the weekly limit is 25 req — avoid burning it silently.
        # Return stub immediately; caller should log a warning once.
        return {"ip": ip, "noise": False, "riot": False,
                "classification": "unknown", "message": "no_api_key"}

    url = f"{_BASE}/{ip}"
    for attempt in range(retries + 1):
        try:
            resp = httpx.get(url, headers=_headers(api_key), timeout=_TIMEOUT)

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 404:
                return {"ip": ip, "noise": False, "riot": False,
                        "classification": "unknown", "message": "not_found"}

            if resp.status_code == 429:
                log.warning("GreyNoise rate limit hit for %s (attempt %d), waiting %.1fs",
                            ip, attempt + 1, _RETRY_WAIT)
                time.sleep(_RETRY_WAIT)
                continue

            # Any other error — return stub, don't crash pipeline
            log.warning("GreyNoise %s for %s", resp.status_code, ip)
            return {"ip": ip, "noise": False, "riot": False,
                    "classification": "unknown", "message": f"http_{resp.status_code}"}

        except httpx.TimeoutException:
            log.warning("GreyNoise timeout for %s (attempt %d/%d)", ip, attempt + 1, retries + 1)
        except Exception as exc:
            log.error("GreyNoise unexpected error for %s: %s", ip, exc)
            return {"ip": ip, "noise": False, "riot": False,
                    "classification": "unknown", "message": "error"}

    return {"ip": ip, "noise": False, "riot": False,
            "classification": "unknown", "message": "retries_exceeded"}


def bulk_lookup(
    ips: List[str],
    api_key: Optional[str] = None,
    delay: float = 0.15,
) -> Dict[str, Dict]:
    """
    Lookup multiple IPs sequentially, respecting rate limits.
    Returns dict: ip -> greynoise_result (always populated — never missing a key).

    If api_key is None, returns stubs for all IPs immediately (no HTTP requests made).
    """
    if not api_key:
        log.warning(
            "GREYNOISE_API_KEY not set — skipping GreyNoise enrichment. "
            "All devices will have classification=unknown. "
            "Register at https://viz.greynoise.io/signup for a free key."
        )
        return {
            ip: {"ip": ip, "noise": False, "riot": False,
                 "classification": "unknown", "message": "no_api_key"}
            for ip in ips
        }

    results: Dict[str, Dict] = {}
    for ip in ips:
        results[ip] = lookup_ip(ip, api_key=api_key)
        if delay > 0:
            time.sleep(delay)
    return results


def parse_classification(gn_data: Optional[Dict]) -> str:
    """
    Returns: 'malicious' | 'benign' | 'noise' | 'unknown'

    Logic:
      - riot=True  → 'benign'    (known CDN / cloud provider)
      - classification='malicious' → 'malicious'
      - noise=True + not malicious → 'noise' (active scanner, not targeted threat)
      - else → 'unknown'
    """
    if not gn_data:
        return "unknown"
    if gn_data.get("riot"):
        return "benign"
    classification = (gn_data.get("classification") or "unknown").lower()
    if classification == "malicious":
        return "malicious"
    if gn_data.get("noise"):
        return "noise"
    return "unknown"


def extract_tags(gn_data: Optional[Dict]) -> List[str]:
    """Extract threat tags (available on paid tiers only; empty list on free)."""
    if not gn_data:
        return []
    return gn_data.get("tags") or []
