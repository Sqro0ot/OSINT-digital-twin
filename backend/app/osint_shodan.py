# app/osint_shodan.py
"""
OSINT data collection module — Layer 1 (Data Collection Layer).

Data source: Shodan InternetDB  https://internetdb.shodan.io/{ip}
--------------------------------------------------------------------
Бесплатный публичный endpoint, не требует API-ключа.
Endpoint: GET https://internetdb.shodan.io/{ip}
Возвращает: ports, vulns (CVE), cpes, hostnames, tags.
Rate limit: ~100 req/мин.
"""

import time
import logging
from typing import List

import requests
from sqlalchemy.orm import Session

from .models import RawShodan

log = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "osint-collector/1.0"})


def fetch_shodan_cameras(db: Session, ips: List[str], delay: float = 0.7) -> int:
    """
    Запрашивает InternetDB для каждого IP из списка
    и сохраняет сырые данные в таблицу raw_shodan.

    Args:
        db:    Сессия SQLAlchemy.
        ips:   Список IPv4-адресов.
        delay: Пауза между запросами (сек).

    Returns:
        Количество успешно сохранённых записей.
    """
    count = 0

    for ip in ips:
        try:
            resp = _SESSION.get(INTERNETDB_URL.format(ip=ip), timeout=10)

            if resp.status_code == 404:
                log.info("[osint_shodan] %s — нет данных в InternetDB", ip)
                time.sleep(delay)
                continue

            resp.raise_for_status()
            host = resp.json()

        except requests.RequestException as e:
            log.warning("[osint_shodan] host(%s) error: %s", ip, e)
            time.sleep(delay)
            continue

        # InternetDB не даёт гео, ставим None
        row = RawShodan(
            ip=host.get("ip", ip),
            city=None,
            country=None,
            latitude=None,
            longitude=None,
            data={
                "ip_str":    host.get("ip", ip),
                "ports":     host.get("ports", []),
                "vulns":     host.get("vulns", []),
                "cpes":      host.get("cpes", []),
                "hostnames": host.get("hostnames", []),
                "tags":      host.get("tags", []),
            },
        )

        # upsert: обновить если IP уже есть
        existing = db.query(RawShodan).filter(RawShodan.ip == row.ip).first()
        if existing:
            existing.data = row.data
        else:
            db.add(row)

        count += 1
        log.info(
            "[osint_shodan] %s — ports: %s, CVEs: %d",
            ip,
            host.get("ports", []),
            len(host.get("vulns", [])),
        )
        time.sleep(delay)

    db.commit()
    return count
