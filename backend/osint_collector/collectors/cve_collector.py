import requests
from typing import List
from collectors.base import BaseCollector
from models import OSINTRecord

class CVECollector(BaseCollector):
    source_name = "cve"
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(self, query: str) -> List[dict]:
        """query - ключевое слово, например 'hikvision'"""
        params = {"keywordSearch": query, "resultsPerPage": 20}
        resp = requests.get(self.BASE_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", [])

    def normalize(self, raw: dict) -> OSINTRecord:
        cve = raw.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})

        # Извлечь CVSS score
        cvss_score = 0.0
        cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV2", []))
        if cvss_data:
            cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0.0)

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        return OSINTRecord(
            source=self.source_name,
            entity_type="vulnerability",
            entity_id=cve_id,
            attributes={
                "description": desc_en[:300],
                "cvss_score":  cvss_score,
                "severity":    self._severity(cvss_score),
                "published":   cve.get("published"),
                "references":  [r["url"] for r in cve.get("references", [])[:3]],
            },
            tags=["vulnerability", self._severity(cvss_score).lower()],
            cve_ids=[cve_id],
            confidence=0.95,
            risk_score=cvss_score * 10,
        )

    def _severity(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"
