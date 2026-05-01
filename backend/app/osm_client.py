# app/osm_client.py
import math
import logging
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger(__name__)

OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]

ALMATY_BBOX = (43.15, 76.80, 43.40, 77.10)

HEADERS = {
    "User-Agent": "OSINT-DigitalTwin-Diploma/1.0 (academic research; github.com/Sqro0ot/OSINT-digital-twin)",
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
}

# Jitter step (~110 m) so two IP-addresses that map to the same OSM node
# don't overlap on the map.  Each IP gets a deterministic offset derived
# from its hash, so the position is stable across restarts.
_JITTER_DEG = 0.001  # ≈ 111 m per degree


def _build_query() -> str:
    south, west, north, east = ALMATY_BBOX
    bbox_str = f"{south},{west},{north},{east}"
    return (
        f'[out:json][timeout:30][bbox:{bbox_str}];'
        '('
        'node["man_made"="surveillance"];'
        'node["highway"="traffic_signals"];'
        'node["amenity"="parking"]["access"!="private"];'
        ');'
        'out body;'
    )


def fetch_almaty_infrastructure() -> List[Dict]:
    query = _build_query()
    for mirror in OVERPASS_MIRRORS:
        try:
            resp = requests.post(
                mirror, data={"data": query}, headers=HEADERS, timeout=35,
            )
            if resp.status_code in (429, 406):
                log.warning("[osm] %s returned %s, trying next mirror", mirror, resp.status_code)
                continue
            resp.raise_for_status()
            nodes = [
                el for el in resp.json().get("elements", [])
                if el.get("lat") and el.get("lon")
            ]
            log.info("[osm] Fetched %d infrastructure nodes from %s", len(nodes), mirror)
            return nodes
        except requests.RequestException as exc:
            log.warning("[osm] Mirror %s failed: %s", mirror, exc)
            continue
    log.warning("[osm] All Overpass mirrors failed. Using mock coordinates.")
    return []


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _deterministic_jitter(ip: str) -> Tuple[float, float]:
    """
    Возвращает детерминированный (lat, lon) jitter для IP.
    Использует два независимых хеша чтобы lat и lon смещались по-разному.
    Диапазон: ±_JITTER_DEG (~±111 м).
    """
    h1 = hash(ip + "_lat")
    h2 = hash(ip + "_lon")
    # Нормируем в диапазон [-1, 1] через модуль простого числа
    dlat = ((h1 % 1000) / 1000.0 - 0.5) * 2 * _JITTER_DEG
    dlon = ((h2 % 1000) / 1000.0 - 0.5) * 2 * _JITTER_DEG
    return dlat, dlon


def resolve_coordinates(
    ip: str,
    fallback_lat: Optional[float],
    fallback_lon: Optional[float],
    osm_nodes: List[Dict],
) -> Tuple[Optional[float], Optional[float], str]:
    """
    Каждый IP получает свой детерминированный OSM-узел через hash(ip) % len(nodes),
    плюс небольшой jitter (~±110 м) чтобы точки не сливались на карте.
    Если OSM недоступен — используем fallback_lat/lon + jitter.
    """
    dlat, dlon = _deterministic_jitter(ip)

    if osm_nodes:
        idx = hash(ip) % len(osm_nodes)
        node = osm_nodes[idx]
        return float(node["lat"]) + dlat, float(node["lon"]) + dlon, "osm_hash"

    if fallback_lat is not None and fallback_lon is not None:
        return fallback_lat + dlat, fallback_lon + dlon, "mock_jitter"

    return None, None, "none"
