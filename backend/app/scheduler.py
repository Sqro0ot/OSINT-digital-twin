from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from .db import SessionLocal
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets

scheduler = BackgroundScheduler()


def job_shodan():
    db: Session = SessionLocal()
    try:
        fetch_shodan_cameras(db, limit=50)
    finally:
        db.close()


def job_normalize():
    db: Session = SessionLocal()
    try:
        normalize_shodan_hosts(db, batch_size=200)
    finally:
        db.close()


def job_sync():
    db: Session = SessionLocal()
    try:
        sync_devices_to_assets(db, limit=200)
    finally:
        db.close()


def start_scheduler():
    # Shodan fetch раз в сутки
    scheduler.add_job(job_shodan, "interval", hours=24)
    # Нормализация каждые 6 часов
    scheduler.add_job(job_normalize, "interval", hours=6)
    # Синхронизация с цифровым двойником каждые 6 часов
    scheduler.add_job(job_sync, "interval", hours=6)
    scheduler.start()
