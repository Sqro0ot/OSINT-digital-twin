# app/scheduler.py
"""
Background job scheduler for the OSINT Digital Twin pipeline.

Pipeline execution order (every 24h cycle):
  1. job_shodan     — InternetDB enriches each IP from TARGET_IPS
  2. job_normalize  — normalises raw data + EPSS + OSM geo
  3. job_sync       — syncs NormalizedDevice -> Asset (Digital Twin)

Schedule:
  job_shodan:    every 24h
  job_normalize: every 6h
  job_sync:      every 6h
"""

import logging
from typing import List

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from .db import SessionLocal
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler()

# Static target IPs for Shodan enrichment.
# Extend with real IPs from a device registry or manual list.
TARGET_IPS: List[str] = [
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


def job_shodan() -> None:
    """
    Layer 1: Shodan InternetDB enrichment.
    Fetches open ports, CVE tags, and banners for each IP in TARGET_IPS.
    """
    if not TARGET_IPS:
        log.warning("[scheduler] job_shodan: TARGET_IPS is empty, skipping")
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
    Enriches CVEs with EPSS scores, resolves coordinates via OSM,
    computes confidence score.
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
      job_shodan:    every 24h
      job_normalize: every 6h
      job_sync:      every 6h

    On startup, Shodan job runs immediately to populate data.
    """
    job_shodan()

    scheduler.add_job(job_shodan,    "interval", hours=24, id="shodan")
    scheduler.add_job(job_normalize, "interval", hours=6,  id="normalize")
    scheduler.add_job(job_sync,      "interval", hours=6,  id="sync")
    scheduler.start()
    log.info("[scheduler] all jobs started")
