# app/censys_client.py
import logging
import os
from typing import List, Optional

import requests

log = logging.getLogger(__name__)

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"

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

MAX_RESULTS = 100


def _get_credentials() -> Optional[tuple]:
    """
    Returns (api_id, api_secret) tuple for Censys Basic Auth.
    Reads from pydantic Settings first, then os.environ fallback.
    Returns None if credentials are not set.
    """
    try:
        from .config import settings
        api_id = getattr(settings, 'CENSYS_API_ID', None) or os.environ.get('CENSYS_API_ID')
        api_secret = getattr(settings, 'CENSYS_API_SECRET', None) or os.environ.get('CENSYS_API_SECRET')
    except Exception:
        api_id = os.environ.get('CENSYS_API_ID')
        api_secret = os.environ.get('CENSYS_API_SECRET')

    if api_id and api_secret:
        return api_id, api_secret
    return None


def discover_kz_devices(
    query: str = DEFAULT_QUERY,
    max_results: int = MAX_RESULTS,
) -> List[str]:
    """
    Searches Censys Search API for IoT/camera devices in Kazakhstan.
    Uses HTTP Basic Auth with API ID + Secret.

    Returns list of discovered IPv4 addresses.
    Returns empty list if credentials missing or request fails.
    """
    creds = _get_credentials()
    if not creds:
        log.warning(
            "[censys] CENSYS_API_ID or CENSYS_API_SECRET not set. "
            "Add credentials to .env (see .env.example). "
            "Skipping Censys discovery."
        )
        return []

    api_id, api_secret = creds
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
                auth=(api_id, api_secret),   # Basic Auth
                params=params,
                timeout=20,
            )

            if resp.status_code == 401:
                log.error(
                    "[censys] Authentication failed (401). "
                    "Check CENSYS_API_ID and CENSYS_API_SECRET in .env."
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


def get_censys_host_details(ip: str) -> Optional[dict]:
    creds = _get_credentials()
    if not creds:
        return None
    api_id, api_secret = creds
    try:
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(api_id, api_secret),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("result")
    except requests.RequestException as exc:
        log.warning("[censys] Host detail fetch failed for %s: %s", ip, exc)
        return None
