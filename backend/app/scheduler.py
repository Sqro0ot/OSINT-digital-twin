from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from .db import SessionLocal
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets

scheduler = BackgroundScheduler()

# Список целевых IP-адресов для прототипа (дорожные камеры Алматы).
# В production-версии этот список формируется из реестра устройств
# или конфигурационного файла.
TARGET_IPS: list[str] = [
    # Эти IP предоставлены в учебных целях и соответствуют
    # публичным данным InternetDB для демонстрации прототипа.
    # Замените на реальные IP из государственного реестра ИКТ-оборудования.
]


def job_shodan():
    """Периодический сбор OSINT-данных через InternetDB Shodan.

    Запускается раз в 24 часа. Если TARGET_IPS пуст — пропускает сбор
    и логирует предупреждение. В production-версии список IP должен
    заполняться из внешнего реестра.
    """
    if not TARGET_IPS:
        print(
            "[scheduler] job_shodan: TARGET_IPS is empty. "
            "Populate the list to enable automatic collection."
        )
        return
    db: Session = SessionLocal()
    try:
        fetch_shodan_cameras(db, ips=TARGET_IPS)
    finally:
        db.close()


def job_normalize():
    """Нормализация сырых OSINT-данных в NormalizedDevice.

    Запускается каждые 6 часов. Обрабатывает батч до 200 записей за раз.
    """
    db: Session = SessionLocal()
    try:
        normalize_shodan_hosts(db, batch_size=200)
    finally:
        db.close()


def job_sync():
    """Синхронизация нормализованных устройств с цифровым двойником (Assets).

    Запускается каждые 6 часов. Ограничение CAMERA_LIMIT = 3 задаётся
    в twin.py и предназначено для прототипной демонстрации.
    """
    db: Session = SessionLocal()
    try:
        sync_devices_to_assets(db, limit=200)
    finally:
        db.close()


def start_scheduler():
    """Запускает все фоновые задачи APScheduler.

    Расписание:
    - job_shodan:    каждые 24 ч (сбор OSINT из InternetDB)
    - job_normalize: каждые 6 ч  (нормализация сырых данных)
    - job_sync:      каждые 6 ч  (синхронизация с цифровым двойником)
    """
    scheduler.add_job(job_shodan, "interval", hours=24)
    scheduler.add_job(job_normalize, "interval", hours=6)
    scheduler.add_job(job_sync, "interval", hours=6)
    scheduler.start()
