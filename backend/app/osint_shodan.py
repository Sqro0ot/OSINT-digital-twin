# app/osint_shodan.py
"""
OSINT data collection module — Layer 1 (Data Collection Layer).

Data source: Shodan REST API  https://api.shodan.io/shodan/host/{ip}
--------------------------------------------------------------------
Uses api.host(ip) from the official `shodan` Python library.
Works on the FREE Shodan plan (requires API key, no query credits needed).

Endpoint:  GET https://api.shodan.io/shodan/host/{ip}?key=API_KEY
Returns:   ports, banners, CVEs, geo, org, ISP, SSL, tags.

Rate limit: 1 req/sec on free plan.
"""

import time
import logging
from typing import List

import shodan
from sqlalchemy.orm import Session

from .models import RawShodan
from .config import settings

log = logging.getLogger(__name__)


def fetch_shodan_cameras(db: Session, ips: List[str], delay: float = 1.1) -> int:
    """
    Запрашивает Shodan api.host(ip) для каждого IP из списка
    и сохраняет сырые данные в таблицу raw_shodan.

    Args:
        db:    Сессия SQLAlchemy.
        ips:   Список IPv4-адресов.
        delay: Пауза между запросами (сек). Free plan: 1 req/sec.

    Returns:
        Количество успешно сохранённых записей.
    """
    api = shodan.Shodan(settings.SHODAN_API_KEY)
    count = 0

    for ip in ips:
        try:
            host = api.host(ip)
        except shodan.APIError as e:
            log.warning("[osint_shodan] host(%s) error: %s", ip, e)
            time.sleep(delay)
            continue

        location = host.get("location", {})

        row = RawShodan(
            ip=host.get("ip_str", ip),
            city=location.get("city"),
            country=location.get("country_name"),
            latitude=location.get("latitude"),
            longitude=location.get("longitude"),
            data=host,
        )

        # upsert: обновить если IP уже есть
        existing = db.query(RawShodan).filter(RawShodan.ip == row.ip).first()
        if existing:
            existing.data      = host
            existing.city      = row.city
            existing.country   = row.country
            existing.latitude  = row.latitude
            existing.longitude = row.longitude
        else:
            db.add(row)

        count += 1
        log.info("[osint_shodan] %s — %d services, %d CVEs",
                 ip,
                 len(host.get("data", [])),
                 len(host.get("vulns", {})))
        time.sleep(delay)

    db.commit()
    return count
