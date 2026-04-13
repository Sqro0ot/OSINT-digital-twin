# app/osint_shodan.py
"""
OSINT data collection module — Layer 1 (Data Collection Layer).

Data source: **Shodan InternetDB** (https://internetdb.shodan.io)
-------------------------------------------------------------------
This module uses the **free, unauthenticated** InternetDB endpoint provided
by Shodan, NOT the paid Shodan API.  Key differences:

+-------------------------+------------------------------+-------------------------------+
| Parameter               | InternetDB (this module)     | Full Shodan API               |
+=========================+==============================+===============================+
| Cost                    | Free, no API key             | $59+/month                    |
+-------------------------+------------------------------+-------------------------------+
| Data per IP             | Ports, CVEs, tags, hostnames | Full banners, history, geo    |
+-------------------------+------------------------------+-------------------------------+
| Geolocation             | Not returned                 | Country, city, coordinates    |
+-------------------------+------------------------------+-------------------------------+
| Search by country/org   | No                           | Yes (full query syntax)       |
+-------------------------+------------------------------+-------------------------------+
| Rate limit              | Undocumented (be respectful) | Plan-dependent                |
+-------------------------+------------------------------+-------------------------------+

Because InternetDB does not return geolocation data, the normalisation
pipeline (``normalize.py``) fills coordinates from ``mock_locations.FREE_COORDS``
in prototype mode.  In production, ``infra/GeoLite2-City.mmdb`` (MaxMind) is
intended to replace mock coordinates with real IP geolocation.

Production upgrade path
-----------------------
To upgrade to the full Shodan API, set ``SHODAN_API_KEY`` in ``.env`` and
replace the ``requests.get(INTERNETDB_URL)`` call with ``shodan.Shodan(key).host(ip)``
(the ``shodan`` library is already listed in ``requirements.txt``).
"""

import requests
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from .models import RawCensys

INTERNETDB_URL = "https://internetdb.shodan.io"


def fetch_shodan_cameras(db: Session, ips: List[str]) -> int:
    """Запрашивает InternetDB для каждого IP из списка и сохраняет сырые данные.

    Args:
        db:  Сессия SQLAlchemy.
        ips: Список IPv4-адресов для проверки.
             В прототипе формируется через scheduler.TARGET_IPS.
             В production — из внешнего реестра устройств.

    Returns:
        Количество успешно сохранённых записей RawCensys.
    """
    count = 0

    for ip in ips:
        try:
            resp = requests.get(f"{INTERNETDB_URL}/{ip}", timeout=10)
            if resp.status_code == 404:
                print(f"[osint_internetdb] No data for {ip}")
                continue

            resp.raise_for_status()
            host: Dict[str, Any] = resp.json()
        except requests.RequestException as e:
            print(f"[osint_internetdb] InternetDB error for {ip}: {e}")
            continue

        # InternetDB не возвращает геолокацию — поля city/lat/lon будут
        # заполнены из mock_locations.FREE_COORDS на этапе нормализации.
        row = RawCensys(
            ip=host.get("ip", ip),
            city=None,
            country=None,
            latitude=None,
            longitude=None,
            data=host,
        )
        db.add(row)
        count += 1

    db.commit()
    return count
