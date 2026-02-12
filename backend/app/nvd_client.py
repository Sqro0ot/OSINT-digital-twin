# app/nvd_client.py

from typing import Optional
import time
import logging
import requests

log = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss_for_cve(cve_id: str, api_key: Optional[str] = None) -> Optional[float]:
    """
    Возвращает baseScore CVSS (v3.1/v3.0/v2) для указанного CVE.
    Если ничего не найдено или произошла ошибка — None.
    """
    params = {"cveId": cve_id}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None

        metrics = vulns[0].get("cve", {}).get("metrics", {})

        # CVSS v3.1
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            return m["cvssData"]["baseScore"]

        # CVSS v3.0
        if "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            return m["cvssData"]["baseScore"]

        # CVSS v2
        if "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            return m["cvssData"]["baseScore"]

        return None

    except Exception as exc:
        log.warning("Failed to fetch CVSS for %s: %s", cve_id, exc)
        return None


def backfill_rawcve_scores(db_session, api_key: Optional[str] = None, batch_size: int = 100):
    """
    Проходит по rawcve без cvss_score, подкачивает CVSS из NVD
    и сохраняет в БД.
    """
    from .models import RawCVE  # локальный импорт, чтобы избежать циклов

    q = (
        db_session.query(RawCVE)
        .filter(RawCVE.cvss_score.is_(None))
        .order_by(RawCVE.cve_id)
    )

    total = q.count()
    log.info("Backfilling CVSS scores for %d CVEs", total)

    processed = 0
    for row in q.yield_per(batch_size):
        score = fetch_cvss_for_cve(row.cve_id, api_key=api_key)
        if score is not None:
            row.cvss_score = score
        processed += 1

        if processed % batch_size == 0:
            db_session.commit()
            log.info("Processed %d / %d CVEs", processed, total)
            # чтобы не душить NVD, маленькая пауза
            time.sleep(0.5)

    db_session.commit()
    log.info("Backfill finished, processed %d CVEs", processed)
