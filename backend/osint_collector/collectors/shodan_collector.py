import shodan
from typing import List
from collectors.base import BaseCollector
from models import OSINTRecord
from config import config

class ShodanCollector(BaseCollector):
    source_name = "shodan"

    def __init__(self):
        self.api = shodan.Shodan(config.SHODAN_API_KEY)

    def fetch(self, query: str) -> List[dict]:
        result = self.api.search(query, limit=100)
        return result.get("matches", [])

    def normalize(self, raw: dict) -> OSINTRecord:
        location = raw.get("location", {})
        return OSINTRecord(
            source=self.source_name,
            entity_type="ip",
            entity_id=raw.get("ip_str", ""),
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
                "vulns":     list(raw.get("vulns", {}).keys()),
            },
            tags=raw.get("tags", []),
            cve_ids=list(raw.get("vulns", {}).keys()),
            confidence=0.85,
        )
