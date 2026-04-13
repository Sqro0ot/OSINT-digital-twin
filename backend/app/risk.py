# app/risk.py
"""
Risk level mapping module.

This module is responsible for converting a raw CVSS base score into a
human-readable risk level label (LOW / MEDIUM / HIGH / CRITICAL).

**IMPORTANT — Two separate concepts in this codebase:**

1. ``cvss_to_level`` (this file) — determines the **threat level** of a
   device based on its maximum CVSS v3.1 score.  The thresholds follow the
   official CVSS v3.1 Qualitative Severity Rating Scale
   (NIST NVD / FIRST):

   - CRITICAL : cvss_max >= 9.0
   - HIGH     : cvss_max >= 7.0
   - MEDIUM   : cvss_max >= 4.0
   - LOW      : cvss_max >  0.0
   - UNKNOWN  : no CVE data available

2. ``compute_confidence`` (normalize.py) — a **separate** weighted score
   (0–1) that rates *how reliable* the collected OSINT data is, using four
   factors:

   - source_score       (weight 0.35) — credibility of the OSINT source
   - freshness_score    (weight 0.25) — how recent the data is
   - confirmation_score (weight 0.20) — corroboration across multiple feeds
   - completeness_score (weight 0.20) — coverage of required data fields

   Formula::

       confidence = 0.35 * source + 0.25 * freshness
                    + 0.20 * confirmation + 0.20 * completeness

Do **not** confuse the two: ``risk_level`` expresses *danger*,
``confidence`` expresses *data quality*.
"""

from typing import Optional


def cvss_to_level(cvss_max: Optional[float]) -> str:
    """Маппинг CVSS v3.1 → уровень риска.

    Пороговые значения соответствуют Qualitative Severity Rating Scale
    стандарта CVSS v3.1 (FIRST / NVD NIST):

    +------------+----------------------+
    | Уровень     | Диапазон CVSS v3.1   |
    +============+======================+
    | CRITICAL   | 9.0 – 10.0           |
    +------------+----------------------+
    | HIGH       | 7.0 – 8.9            |
    +------------+----------------------+
    | MEDIUM     | 4.0 – 6.9            |
    +------------+----------------------+
    | LOW        | 0.1 – 3.9            |
    +------------+----------------------+
    | UNKNOWN    | нет данных (None)   |
    +------------+----------------------+

    Args:
        cvss_max: Максимальный CVSS base score среди всех
                   CVE устройства, или None если CVE-данных нет.

    Returns:
        Строка: "CRITICAL", "HIGH", "MEDIUM", "LOW" или "UNKNOWN".
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
