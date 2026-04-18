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


def _get_pat() -> Optional[str]:
    """
    Reads CENSYS_PAT with two fallback strategies:
      1. pydantic Settings object (reads .env via pathlib-resolved path)
      2. os.environ (works when the variable is exported in the shell)
    This ensures the token is found regardless of the working directory
    from which uvicorn is launched.
    """
    # Strategy 1: pydantic settings (resolves .env by file location)
    try:
        from .config import settings
        if settings.CENSYS_PAT:
            return settings.CENSYS_PAT
    except Exception:
        pass

    # Strategy 2: raw environment variable
    return os.environ.get("CENSYS_PAT")


def discover_kz_devices(
    query: str = DEFAULT_QUERY,
    max_results: int = MAX_RESULTS,
) -> List[str]:
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
                    "[censys] Authentication failed (401). "
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
