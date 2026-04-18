# app/censys_client.py
"""
Censys Search API client — Layer 0 (Device Discovery).

Data source: Censys Search API v2 (https://search.censys.io/api)
-----------------------------------------------------------------
This module implements the discovery layer of the OSINT pipeline.
Unlike Shodan InternetDB (which requires a known IP), Censys allows
searching by country, ASN, labels, and protocol — discovering
unknown devices in Kazakhstan without a pre-built IP list.

Authentication: Personal Access Token (PAT)
  Set CENSYS_PAT in your .env file (see .env.example).
  Free tier: 250 queries/month.

Pipeline role
-------------
Layer 0 — Discovery  →  produces TARGET_IPS list
Layer 1 — Enrichment →  Shodan InternetDB enriches each discovered IP
Layer 1 — Severity   →  NVD API provides CVSS scores
Layer 1b — Threat    →  EPSS provides exploitation probability
Layer 1b — Geo       →  OSM provides real coordinates

Diploma relevance
-----------------
Solves the empty TARGET_IPS problem in scheduler.py:
Censys autonomously discovers IoT devices in Kazakhstan
(traffic cameras, industrial controllers) and feeds their IPs
into the rest of the pipeline — enabling true OSINT discovery
rather than manual IP list maintenance.
"""

import logging
import os
from typing import List, Optional

import requests

log = logging.getLogger(__name__)

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"

# Camera/IoT vendor labels recognised by Censys
DEFAULT_QUERY = (
    'country_code: KZ and ('
    'labels: hikvision or '
    'labels: dahua or '
    'labels: axis or '
    'services.service_name: RTSP or '
    'services.port: 554 or '
    'services.port: 8000 or '
    'services.port: 8080'
    ')'
)

MAX_RESULTS = 100   # max devices per discovery run (free tier: 250 req/month)


def _get_pat() -> Optional[str]:
    """Reads Censys PAT from environment variable CENSYS_PAT."""
    return os.environ.get("CENSYS_PAT")


def discover_kz_devices(
    query: str = DEFAULT_QUERY,
    max_results: int = MAX_RESULTS,
) -> List[str]:
    """
    Searches Censys for IoT/camera devices in Kazakhstan.

    Args:
        query:       Censys search query string.
        max_results: Maximum number of IPs to return.

    Returns:
        List of discovered IPv4 address strings.
        Returns empty list if PAT is missing or request fails.

    Usage in scheduler.py:
        from .censys_client import discover_kz_devices
        TARGET_IPS = discover_kz_devices()
    """
    pat = _get_pat()
    if not pat:
        log.warning(
            "[censys] CENSYS_PAT not set. "
            "Add your Personal Access Token to .env (see .env.example). "
            "Skipping Censys discovery."
        )
        return []

    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/json",
    }

    ips: List[str] = []
    cursor: Optional[str] = None
    pages_fetched = 0

    while len(ips) < max_results:
        params = {"q": query, "per_page": min(100, max_results - len(ips))}
        if cursor:
            params["cursor"] = cursor

        try:
            resp = requests.get(
                CENSYS_SEARCH_URL,
                headers=headers,
                params=params,
                timeout=20,
            )

            if resp.status_code == 401:
                log.error(
                    "[censys] Authentication failed. "
                    "Check your CENSYS_PAT value in .env."
                )
                break

            if resp.status_code == 429:
                log.warning("[censys] Rate limit reached. Stopping discovery.")
                break

            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as exc:
            log.error("[censys] Request error: %s", exc)
            break

        result = data.get("result", {})
        hits = result.get("hits", [])

        for hit in hits:
            ip = hit.get("ip")
            if ip:
                ips.append(ip)

        pages_fetched += 1
        cursor = result.get("links", {}).get("next")
        if not cursor or not hits:
            break

    log.info(
        "[censys] Discovery complete: %d IPs found in %d page(s)",
        len(ips),
        pages_fetched,
    )
    return ips


def get_censys_host_details(ip: str, pat: Optional[str] = None) -> Optional[dict]:
    """
    Fetches detailed host information from Censys for a single IP.
    Provides richer data than InternetDB: TLS certs, ASN, full banners.

    Args:
        ip:  IPv4 address string.
        pat: PAT override; uses CENSYS_PAT env var if not provided.

    Returns:
        Host detail dict from Censys API, or None on error.
    """
    token = pat or _get_pat()
    if not token:
        log.warning("[censys] CENSYS_PAT not set — skipping host detail fetch.")
        return None

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("result")
    except requests.RequestException as exc:
        log.warning("[censys] Host detail fetch failed for %s: %s", ip, exc)
        return None
