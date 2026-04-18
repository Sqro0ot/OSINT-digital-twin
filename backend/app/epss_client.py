# app/epss_client.py
"""
EPSS (Exploit Prediction Scoring System) client — Layer 1b (Threat Intel).

Data source: FIRST.org EPSS API v3 (https://api.first.org/data/v1/epss)
----------------------------------------------------------------------
EPSS provides a daily-updated probability score (0.0 – 1.0) indicating
the likelihood that a given CVE will be exploited in the wild within
the next 30 days.  It complements CVSS (which measures severity) with
an exploitability dimension.

No API key required.  Rate limit: undocumented; 1 req/s is safe.

Integration point
-----------------
Called from normalize.py during the normalization pipeline:
  1. collect CVE IDs from RawCensys records
  2. batch-fetch EPSS scores via fetch_epss_scores()
  3. store scores alongside vulnerabilities
  4. compute_confidence() uses epss_max as exploitation weight

Diploma relevance
-----------------
Adds a third independent data dimension to the OSINT pipeline:
  - Shodan InternetDB  → network exposure (open ports, CVE tags)
  - NVD API            → vulnerability severity (CVSS score)
  - EPSS API           → exploitation probability (real-world threat)
"""

import time
import logging
from typing import Dict, List, Optional

import requests

log = logging.getLogger(__name__)

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 30          # EPSS accepts up to ~100 CVEs per request
REQUEST_DELAY = 0.5      # seconds between batches


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """
    Fetches EPSS probability scores for a list of CVE IDs.

    Splits the list into batches of BATCH_SIZE to avoid hitting
    URL length limits.  Returns a dict mapping CVE ID → EPSS score.
    CVEs not found in EPSS are omitted from the result.

    Args:
        cve_ids: List of CVE identifiers, e.g. ["CVE-2021-44228", ...]

    Returns:
        Dict mapping CVE ID to EPSS probability score (0.0 – 1.0).
        Example: {"CVE-2021-44228": 0.9754, "CVE-2022-30190": 0.8821}
    """
    if not cve_ids:
        return {}

    scores: Dict[str, float] = {}
    unique_ids = list(set(cve_ids))

    for i in range(0, len(unique_ids), BATCH_SIZE):
        batch = unique_ids[i: i + BATCH_SIZE]
        cve_param = ",".join(batch)

        try:
            resp = requests.get(
                EPSS_API_BASE,
                params={"cve": cve_param},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("data", []):
                cve_id = item.get("cve")
                epss_val = item.get("epss")
                if cve_id and epss_val is not None:
                    try:
                        scores[cve_id] = float(epss_val)
                    except (ValueError, TypeError):
                        pass

        except requests.RequestException as exc:
            log.warning("[epss] Request failed for batch %d: %s", i // BATCH_SIZE, exc)

        if i + BATCH_SIZE < len(unique_ids):
            time.sleep(REQUEST_DELAY)

    log.info("[epss] Fetched EPSS scores for %d / %d CVEs", len(scores), len(unique_ids))
    return scores


def enrich_vulns_with_epss(
    vulns: List[Dict],
    epss_map: Dict[str, float],
) -> List[Dict]:
    """
    Adds 'epss_score' field to each vulnerability dict that has a matching
    CVE ID in epss_map.

    Args:
        vulns:    List of vulnerability dicts (from normalize.py pipeline).
        epss_map: CVE ID → EPSS score mapping from fetch_epss_scores().

    Returns:
        Updated list of vulnerability dicts with 'epss_score' injected.
    """
    for v in vulns:
        cve_id = v.get("cve_id")
        if cve_id and cve_id in epss_map:
            v["epss_score"] = epss_map[cve_id]
    return vulns


def compute_epss_max(vulns: List[Dict]) -> Optional[float]:
    """
    Returns the maximum EPSS score across all vulnerabilities.
    Used as the exploitation_score component in compute_confidence().

    Returns None if no EPSS scores are present.
    """
    scores = [
        v["epss_score"]
        for v in vulns
        if isinstance(v.get("epss_score"), (int, float))
    ]
    return max(scores) if scores else None
