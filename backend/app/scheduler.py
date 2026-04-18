# app/scheduler.py
"""
Background job scheduler for the OSINT Digital Twin pipeline.

Pipeline execution order (every 24h cycle):
  1. job_discover   — Censys discovers KZ IoT devices → populates TARGET_IPS
  2. job_shodan     — InternetDB enriches each discovered IP
  3. job_normalize  — normalises raw data + EPSS + OSM geo
  4. job_sync       — syncs NormalizedDevice → Asset (Digital Twin)

Schedule:
  job_discover:  every 24h (Censys free tier: 250 req/month)
  job_shodan:    every 24h, 5 min after discovery
  job_normalize: every 6h
  job_sync:      every 6h
"""

import logging
from typing import List

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from .db import SessionLocal
from .censys_client import discover_kz_devices
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler()

# Dynamically populated by job_discover().
# Fallback static IPs for offline/demo mode when Censys PAT is not set.
# Replace or extend with real IPs from a device registry if needed.
TARGET_IPS: List[str] = []

FALLBACK_IPS: List[str] = [
    # Public demo IPs — Hikvision/Dahua devices visible in InternetDB.
    # Used only when Censys discovery returns no results.
    # Safe to query: data is already public on internetdb.shodan.io.
    "77.91.122.107",
    "77.91.122.108",
    "77.91.126.51",
    "95.56.233.12",
    "95.56.233.15",
    "94.247.130.82",
    "94.247.130.91",
    "213.230.106.44",
    "213.230.106.45",
    "5.59.205.16",
]


def job_discover() -> None:
    """
    Layer 0: Censys device discovery.
    Queries Censys Search API for IoT/camera devices in Kazakhstan
    and updates TARGET_IPS for the next Shodan enrichment cycle.

    Falls back to FALLBACK_IPS if:
      - CENSYS_PAT is not set in .env
      - Censys API returns no results
      - Network error
    """
    global TARGET_IPS

    log.info("[scheduler] job_discover: starting Censys discovery")
    discovered = discover_kz_devices()

    if discovered:
        TARGET_IPS = discovered
        log.info(
            "[scheduler] job_discover: discovered %d IPs via Censys",
            len(TARGET_IPS),
        )
    else:
        TARGET_IPS = FALLBACK_IPS
        log.warning(
            "[scheduler] job_discover: Censys returned no results, "
            "using %d fallback IPs",
            len(TARGET_IPS),
        )


def job_shodan() -> None:
    """
    Layer 1: Shodan InternetDB enrichment.
    Fetches open ports, CVE tags, and banners for each IP in TARGET_IPS.

    If TARGET_IPS is empty, runs discovery first.
    """
    global TARGET_IPS

    if not TARGET_IPS:
        log.info("[scheduler] job_shodan: TARGET_IPS empty, running discovery first")
        job_discover()

    if not TARGET_IPS:
        log.warning("[scheduler] job_shodan: no IPs available, skipping")
        return

    db: Session = SessionLocal()
    try:
        fetched = fetch_shodan_cameras(db, ips=TARGET_IPS)
        log.info("[scheduler] job_shodan: fetched %d records", fetched)
    finally:
        db.close()


def job_normalize() -> None:
    """
    Layer 2: Data normalisation.
    Runs normalize_shodan_hosts() which internally:
      - enriches CVEs with EPSS scores (epss_client)
      - resolves coordinates via OSM Overpass (osm_client)
      - computes confidence score (5-component formula)
    """
    db: Session = SessionLocal()
    try:
        normalized = normalize_shodan_hosts(db, batch_size=200)
        log.info("[scheduler] job_normalize: normalized %d records", normalized)
    finally:
        db.close()


def job_sync() -> None:
    """
    Layer 3: Digital Twin synchronisation.
    Syncs NormalizedDevice records to Asset table and generates alerts.
    """
    db: Session = SessionLocal()
    try:
        synced = sync_devices_to_assets(db, limit=200)
        log.info("[scheduler] job_sync: synced %d assets", synced)
    finally:
        db.close()


def start_scheduler() -> None:
    """
    Starts all background jobs.

    Schedule:
      job_discover:  every 24h at :00
      job_shodan:    every 24h at :05 (5 min after discovery)
      job_normalize: every 6h
      job_sync:      every 6h

    On startup, discovery runs immediately so TARGET_IPS is populated
    before the first scheduled shodan job fires.
    """
    # Run discovery once on startup to populate TARGET_IPS immediately
    job_discover()

    scheduler.add_job(job_discover,   "interval", hours=24, id="discover")
    scheduler.add_job(job_shodan,     "interval", hours=24, minutes=5, id="shodan")
    scheduler.add_job(job_normalize,  "interval", hours=6,  id="normalize")
    scheduler.add_job(job_sync,       "interval", hours=6,  id="sync")
    scheduler.start()
    log.info("[scheduler] all jobs started")
