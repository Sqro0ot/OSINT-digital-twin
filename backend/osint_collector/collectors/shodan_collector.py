# collectors/shodan_collector.py
"""
Shodan InternetDB IP lookup collector.

Использует бесплатный публичный endpoint https://internetdb.shodan.io/{ip}
вместо платного api.host() — не требует API-ключа.

Возвращает: открытые порты, CVE, CPE, hostnames, теги.
Лимит: ~100 req/мин (без аутентификации).

Doc: https://internetdb.shodan.io/
"""
import time
import logging
from typing import List

import requests

from collectors.base import BaseCollector
from models import OSINTRecord

logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

# IP-адреса устройств Алматы для lookup (камеры, SCADA, контроллеры).
# Можно расширять из внешнего реестра или из результатов GreyNoise.
DEFAULT_IPS: List[str] = [
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

# Тэги продуктов -> подсистема Smart City
PRODUCT_SUBSYSTEM_MAP = {
    "hikvision": "public_safety",
    "dahua":     "public_safety",
    "rtsp":      "public_safety",
    "scada":     "energy",
    "modbus":    "energy",
    "dnp3":      "energy",
    "traffic":   "traffic",
    "siemens":   "traffic",
}


def _guess_subsystem(raw: dict) -> str:
    """Определяет подсистему по CPE и тегам."""
    searchable = " ".join([
        " ".join(raw.get("cpes", [])),
        " ".join(raw.get("tags", [])),
    ]).lower()
    for keyword, subsystem in PRODUCT_SUBSYSTEM_MAP.items():
        if keyword in searchable:
            return subsystem
    return "unknown"


def _calc_risk(cve_ids: List[str], ports: List[int]) -> float:
    """
    Простая формула риска [0.0 – 1.0]:
      - база 0.3
      - +0.1 за каждую CVE (макс +0.4)
      - +0.1 если открыт порт 23/telnet, 445/smb или 3389/rdp
    """
    score = 0.3
    score += min(len(cve_ids) * 0.1, 0.4)
    if any(p in ports for p in [23, 445, 3389]):
        score += 0.1
    return round(min(score, 1.0), 2)


class ShodanCollector(BaseCollector):
    """
    Коллектор на базе Shodan InternetDB (бесплатно, без ключа).
    Каждый вызов run(ip) возвращает список OSINTRecord (один на IP).
    Для batch-обхода используй run_batch(ips).
    """
    source_name = "internetdb"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "osint-collector/1.0"})

    # ------------------------------------------------------------------ #
    # BaseCollector interface                                              #
    # ------------------------------------------------------------------ #

    def fetch(self, query: str) -> List[dict]:
        """
        query — IP-адрес.
        Возвращает список из одного словаря с данными InternetDB.
        """
        try:
            resp = self.session.get(
                INTERNETDB_URL.format(ip=query),
                timeout=10,
            )
            if resp.status_code == 404:
                logger.info("[internetdb] %s — нет данных", query)
                return []
            resp.raise_for_status()
            return [resp.json()]
        except requests.RequestException as e:
            logger.warning("[internetdb] host(%s) error: %s", query, e)
            return []

    def normalize(self, raw: dict) -> OSINTRecord:
        cve_ids = raw.get("vulns", [])
        ports   = raw.get("ports", [])

        return OSINTRecord(
            source=self.source_name,
            entity_type="ip",
            entity_id=raw.get("ip", ""),
            city=None,
            country=None,
            latitude=None,
            longitude=None,
            attributes={
                "ports":     ports,
                "hostnames": raw.get("hostnames", []),
                "cpes":      raw.get("cpes", []),
                "tags":      raw.get("tags", []),
                "vulns":     cve_ids,
            },
            tags=raw.get("tags", []),
            cve_ids=cve_ids,
            subsystem=_guess_subsystem(raw),
            confidence=0.80,
            risk_score=_calc_risk(cve_ids, ports),
        )

    # ------------------------------------------------------------------ #
    # Batch helper                                                         #
    # ------------------------------------------------------------------ #

    def run_batch(self, ips: List[str] = None, delay: float = 0.7) -> List[OSINTRecord]:
        """
        Обходит список IP по одному.
        delay=0.7s — безопасный rate-limit для InternetDB (~85 req/мин).
        Возвращает все OSINTRecord по всем IP.
        """
        targets = ips or DEFAULT_IPS
        all_records: List[OSINTRecord] = []
        for ip in targets:
            records = self.run(ip)
            all_records.extend(records)
            logger.info("[internetdb] %s -> %d records", ip, len(records))
            time.sleep(delay)
        return all_records
