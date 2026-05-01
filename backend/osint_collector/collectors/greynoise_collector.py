# collectors/greynoise_collector.py
"""
GreyNoise Community API collector.

Использует /v3/community/{ip} — бесплатный endpoint с опциональным API-ключом.

Особенность API: 404 значит «не наблюдался», но возвращает валидный JSON
с полями ip/noise/riot/message — обрабатываем как «неизвестный» результат.
Doc: https://developer.greynoise.io/reference/community-api
"""
import logging
from typing import List

import requests

from collectors.base import BaseCollector
from models import OSINTRecord
from config import config

logger = logging.getLogger(__name__)

COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"

# Ключевые слова в поле name -> подсистема Smart City
NAME_SUBSYSTEM_MAP = {
    "shodan":    "network",
    "censys":    "network",
    "masscan":   "network",
    "camera":    "public_safety",
    "hikvision": "public_safety",
    "dahua":     "public_safety",
    "scada":     "energy",
    "modbus":    "energy",
    "siemens":   "traffic",
    "traffic":   "traffic",
}

# Риск по classification
CLASSIFICATION_RISK = {
    "malicious": 0.85,
    "unknown":   0.45,
    "benign":    0.10,
    "not_seen":  0.20,  # IP не наблюдался — низкий риск
}


def _guess_subsystem(name: str) -> str:
    if not name:
        return "unknown"
    name_lower = name.lower()
    for keyword, subsystem in NAME_SUBSYSTEM_MAP.items():
        if keyword in name_lower:
            return subsystem
    return "unknown"


def _calc_risk(classification: str, noise: bool, riot: bool) -> float:
    """
    Риск [0.0 – 1.0]:
      - база по classification
      - noise=True (активный сканер) +0.10
      - riot=True  (известный безопасный сервис) -0.20
    """
    score = CLASSIFICATION_RISK.get(classification, 0.45)
    if noise:
        score += 0.10
    if riot:
        score -= 0.20
    return round(max(0.0, min(score, 1.0)), 2)


class GreyNoiseCollector(BaseCollector):
    """
    Коллектор GreyNoise Community API.
    run(ip) — один OSINTRecord с классификацией, шумом и оценкой риска.
    Особенность: 404 = IP не наблюдался, но всё равно возвращает OSINTRecord.
    """
    source_name = "greynoise"
    BASE_URL = COMMUNITY_URL

    def __init__(self):
        self.session = requests.Session()
        api_key = getattr(config, "GREYNOISE_API_KEY", None)
        if api_key:
            self.session.headers.update({"key": api_key})
        self.session.headers.update({"User-Agent": "osint-collector/1.0"})

    # ------------------------------------------------------------------ #
    # BaseCollector interface                                              #
    # ------------------------------------------------------------------ #

    def fetch(self, query: str) -> List[dict]:
        """query — IP-адрес."""
        try:
            resp = self.session.get(
                self.BASE_URL.format(ip=query),
                timeout=15,
            )
            # 404 = «IP не наблюдался» — всё равно возвращаем валидный JSON
            if resp.status_code in (200, 404):
                data = resp.json()
                # Помечаем что IP не наблюдался
                if resp.status_code == 404:
                    data["_not_seen"] = True
                    logger.info("[greynoise] %s — не наблюдался (404)", query)
                return [data]
            if resp.status_code == 401:
                logger.warning("[greynoise] 401 Unauthorized — проверь GREYNOISE_API_KEY")
                return []
            if resp.status_code == 429:
                logger.warning("[greynoise] 429 Rate limit exceeded")
                return []
            resp.raise_for_status()
            return [resp.json()]
        except requests.RequestException as e:
            logger.error("[greynoise] host(%s) error: %s", query, e)
            return []

    def normalize(self, raw: dict) -> OSINTRecord:
        not_seen = raw.get("_not_seen", False)
        classification = "not_seen" if not_seen else raw.get("classification", "unknown")
        noise = raw.get("noise", False)
        riot  = raw.get("riot", False)
        name  = raw.get("name", "")

        tags = [classification, "greynoise-checked"]
        if noise:
            tags.append("noise")
        if riot:
            tags.append("riot")
        if not_seen:
            tags.append("not-observed")

        return OSINTRecord(
            source=self.source_name,
            entity_type="ip",
            entity_id=raw.get("ip", ""),
            country=raw.get("country"),
            attributes={
                "noise":          noise,
                "riot":           riot,
                "classification": classification,
                "name":           name,
                "last_seen":      raw.get("last_seen"),
                "message":        raw.get("message"),
                "link":           raw.get("link"),
            },
            tags=tags,
            subsystem=_guess_subsystem(name),
            confidence=0.60 if not_seen else 0.75,
            risk_score=_calc_risk(classification, noise, riot),
            last_seen=raw.get("last_seen"),
        )
