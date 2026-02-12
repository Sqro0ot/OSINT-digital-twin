# app/risk.py

from typing import Optional


def cvss_to_level(cvss_max: Optional[float]) -> str:
    """
    Маппинг CVSS v3.1 → уровень.
    [0.1–3.9] LOW, [4.0–6.9] MEDIUM, [7.0–8.9] HIGH, [9.0–10.0] CRITICAL.
    """
    if cvss_max is None:
        return "UNKNOWN"

    if cvss_max >= 9.0:
        return "CRITICAL"
    if cvss_max >= 7.0:
        return "HIGH"
    if cvss_max >= 4.0:
        return "MEDIUM"
    if cvss_max > 0.0:
        return "LOW"
    return "UNKNOWN"
