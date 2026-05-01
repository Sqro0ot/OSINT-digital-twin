# collectors/shodan_collector.py
"""
Shodan IP lookup collector.

Использует api.host(ip) вместо api.search() — работает на бесплатном
API-ключе Shodan (Free/Oss план). Принимает список IP-адресов через
run_batch(), либо одиночный IP через run().

Doc: https://developer.shodan.io/api
"""
import time
import logging
from typing import List

import shodan

from collectors.base import BaseCollector
from models import OSINTRecord
from config import config

logger = logging.getLogger(__name__)

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
    "hikvision":  "public_safety",
    "dahua":      "public_safety",
    "rtsp":       "public_safety",
    "scada":      "energy",
    "modbus":     "energy",
    "dnp3":       "energy",
    "traffic":    "traffic",
    "siemens":    "traffic",
}


def _guess_subsystem(raw: dict) -> str:
    """Определяет подсистему по продукту, сервису и тегам."""
    searchable = " ".join([
        str(raw.get("product", "")),
        str(raw.get("data", "")),
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
      - +0.1 если открыт порт 23/telnet или 445/smb
    """
    score = 0.3
    score += min(len(cve_ids) * 0.1, 0.4)
    if any(p in ports for p in [23, 445, 3389]):
        score += 0.1
    return round(min(score, 1.0), 2)


class ShodanCollector(BaseCollector):
    """
    Коллектор Shodan на базе host()-lookup.
    Каждый вызов run(ip) возвращает список OSINTRecord (один на сервис/порт).
    Для batch-обхода используй run_batch(ips).
    """
    source_name = "shodan"

    def __init__(self):
        self.api = shodan.Shodan(config.SHODAN_API_KEY)

    # ------------------------------------------------------------------ #
    # BaseCollector interface                                              #
    # ------------------------------------------------------------------ #

    def fetch(self, query: str) -> List[dict]:
        """
        query — IP-адрес.
        Возвращает список сервисов (ports/banners) для данного IP.
        """
        try:
            host = self.api.host(query)
            # Добавляем общий контекст IP в каждый сервис
            for svc in host.get("data", []):
                svc["_ip"]       = host.get("ip_str", query)
                svc["_location"] = host.get("location", {})
                svc["_vulns"]    = host.get("vulns", {})
                svc["_tags"]     = host.get("tags", [])
            return host.get("data", [])
        except shodan.APIError as e:
            logger.warning("[shodan] host(%s) error: %s", query, e)
            return []

    def normalize(self, raw: dict) -> OSINTRecord:
        location = raw.get("_location", {})
        cve_ids  = list(raw.get("_vulns", {}).keys())
        ports    = [raw.get("port", 0)]

        return OSINTRecord(
            source=self.source_name,
            entity_type="ip",
            entity_id=raw.get("_ip", raw.get("ip_str", "")),
            city=location.get("city"),
            country=location.get("country_name"),
            latitude=location.get("latitude"),
            longitude=location.get("longitude"),
            attributes={
                "port":      raw.get("port"),
                "transport": raw.get("transport"),
                "product":   raw.get("product"),
                "version":   raw.get("version"),
                "org":       raw.get("org"),
                "isp":       raw.get("isp"),
                "hostnames": raw.get("hostnames", []),
                "banner":    raw.get("data", "")[:500],
                "vulns":     cve_ids,
            },
            tags=raw.get("_tags", []) + raw.get("tags", []),
            cve_ids=cve_ids,
            subsystem=_guess_subsystem(raw),
            confidence=0.90,
            risk_score=_calc_risk(cve_ids, ports),
        )

    # ------------------------------------------------------------------ #
    # Batch helper                                                         #
    # ------------------------------------------------------------------ #

    def run_batch(self, ips: List[str] = None, delay: float = 1.0) -> List[OSINTRecord]:
        """
        Обходит список IP по одному (rate-limit: 1 req/sec по умолчанию).
        Возвращает все OSINTRecord по всем IP.
        """
        targets = ips or DEFAULT_IPS
        all_records: List[OSINTRecord] = []
        for ip in targets:
            records = self.run(ip)
            all_records.extend(records)
            logger.info("[shodan] %s -> %d services", ip, len(records))
            time.sleep(delay)
        return all_records
