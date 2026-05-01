import requests
from typing import List
from collectors.base import BaseCollector
from models import OSINTRecord
from config import config

class GreyNoiseCollector(BaseCollector):
    source_name = "greynoise"
    BASE_URL = "https://api.greynoise.io/v3/community"

    def fetch(self, query: str) -> List[dict]:
        """query здесь - это IP-адрес"""
        headers = {"key": config.GREYNOISE_API_KEY}
        resp = requests.get(f"{self.BASE_URL}/{query}", headers=headers, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [resp.json()]

    def normalize(self, raw: dict) -> OSINTRecord:
        classification = raw.get("classification", "unknown")
        return OSINTRecord(
            source=self.source_name,
            entity_type="ip",
            entity_id=raw.get("ip", ""),
            country=raw.get("country"),
            attributes={
                "noise":          raw.get("noise"),
                "riot":           raw.get("riot"),
                "classification": classification,
                "name":           raw.get("name"),
                "last_seen":      raw.get("last_seen"),
                "message":        raw.get("message"),
            },
            tags=[classification, "greynoise-checked"],
            confidence=0.75,
            last_seen=raw.get("last_seen"),
        )
