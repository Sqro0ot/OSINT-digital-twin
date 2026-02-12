# app/osint_shodan.py

import requests
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from .models import RawCensys

INTERNETDB_URL = "https://internetdb.shodan.io"


def fetch_shodan_cameras(db: Session, ips: List[str]) -> int:
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
