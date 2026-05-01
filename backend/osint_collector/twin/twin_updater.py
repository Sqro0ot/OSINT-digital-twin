import logging
from models import OSINTRecord

logger = logging.getLogger(__name__)

class TwinUpdater:
    """
    Обновляет свойства узлов Digital Twin.
    mock=True  - симуляция (для прототипа)
    mock=False - реальные запросы к API (Azure Digital Twins и др.)
    """
    def __init__(self, base_url: str = "", api_token: str = "", mock: bool = True):
        self.base_url = base_url
        self.api_token = api_token
        self.mock = mock

    def update_asset(self, record: OSINTRecord):
        payload = {
            "twin_id":    record.entity_id,
            "subsystem":  record.subsystem,
            "properties": {
                "source":      record.source,
                "risk_score":  record.risk_score,
                "confidence":  record.confidence,
                "country":     record.country,
                "tags":        record.tags,
                "cve_ids":     record.cve_ids,
                "last_seen":   record.last_seen,
                "attributes":  record.attributes,
            }
        }

        if self.mock:
            logger.info(f"[TwinUpdater MOCK] Update -> {record.entity_id} "
                        f"| risk={record.risk_score} | subsystem={record.subsystem}")
            return payload

        import requests
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        response = requests.post(
            f"{self.base_url}/twins/update",
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def update_batch(self, records: list):
        """Обновить сразу несколько активов"""
        results = []
        for record in records:
            try:
                result = self.update_asset(record)
                results.append(result)
            except Exception as e:
                logger.error(f"[TwinUpdater] Ошибка обновления {record.entity_id}: {e}")
        logger.info(f"[TwinUpdater] Обновлено {len(results)} из {len(records)} активов")
        return results
