# app/osm_client.py
import math
import logging
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger(__name__)

# Overpass API mirrors — tried in order until one succeeds
OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]

# Almaty bounding box: south, west, north, east
ALMATY_BBOX = (43.15, 76.80, 43.40, 77.10)

# Required by Overpass API — identify your client politely
HEADERS = {
    "User-Agent": "OSINT-DigitalTwin-Diploma/1.0 (academic research; github.com/Sqro0ot/OSINT-digital-twin)",
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
}


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
    """
    Queries OSM Overpass API for transport infrastructure nodes in Almaty.
    Tries multiple mirrors if the primary endpoint fails.

    Returns list of OSM node dicts {id, lat, lon, tags}.
    Returns empty list on all errors (caller falls back to mock coords).
    """
    query = _build_query()

    for mirror in OVERPASS_MIRRORS:
        try:
            resp = requests.post(
                mirror,
                data={"data": query},
                headers=HEADERS,
                timeout=35,
            )

            if resp.status_code == 429:
                log.warning("[osm] Rate limited by %s, trying next mirror", mirror)
                continue

            if resp.status_code == 406:
                log.warning(
                    "[osm] 406 Not Acceptable from %s — trying next mirror", mirror
                )
                continue

            resp.raise_for_status()
            data = resp.json()
            nodes = [
                el for el in data.get("elements", [])
                if el.get("lat") and el.get("lon")
            ]
            log.info(
                "[osm] Fetched %d infrastructure nodes from %s", len(nodes), mirror
            )
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


def get_nearest_osm_node(
    lat: float,
    lon: float,
    nodes: List[Dict],
    max_distance_m: float = 500.0,
) -> Optional[Dict]:
    best: Optional[Dict] = None
    best_dist = float("inf")

    for node in nodes:
        node_lat = node.get("lat")
        node_lon = node.get("lon")
        if node_lat is None or node_lon is None:
            continue
        dist = _haversine(lat, lon, node_lat, node_lon)
        if dist < best_dist:
            best_dist = dist
            best = node

    if best is not None and best_dist <= max_distance_m:
        return best
    return None


def resolve_coordinates(
    ip: str,
    fallback_lat: Optional[float],
    fallback_lon: Optional[float],
    osm_nodes: List[Dict],
) -> Tuple[Optional[float], Optional[float], str]:
    if fallback_lat is not None and fallback_lon is not None and osm_nodes:
        node = get_nearest_osm_node(fallback_lat, fallback_lon, osm_nodes)
        if node:
            return node["lat"], node["lon"], "osm_snap"
        return fallback_lat, fallback_lon, "fallback"

    if osm_nodes:
        idx = hash(ip) % len(osm_nodes)
        node = osm_nodes[idx]
        return node["lat"], node["lon"], "osm_assigned"

    return fallback_lat, fallback_lon, "none"
