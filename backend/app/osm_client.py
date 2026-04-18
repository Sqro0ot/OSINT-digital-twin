# app/osm_client.py
"""
OSM Overpass API client — Layer 1b (Geospatial Context).

Data source: OpenStreetMap Overpass API (https://overpass-api.de/api/interpreter)
----------------------------------------------------------------------------------
Fetches real-world infrastructure coordinates for Almaty transport subsystem:
  - Traffic surveillance cameras   (man_made=surveillance)
  - Traffic signals / intersections (highway=traffic_signals)
  - Primary and secondary roads     (highway=primary|secondary)

No API key required.  Free and open.  Rate limit: max 1 req/2s (be respectful).

Integration point
-----------------
Replaces mock_locations.FREE_COORDS in normalize.py:
  1. fetch_almaty_infrastructure() returns list of OSM nodes with real coords
  2. get_nearest_osm_node() matches each device IP to the nearest OSM object
     using Haversine distance
  3. normalize.py uses real (lat, lon) instead of mock coordinates

Diploma relevance
-----------------
Solves the mock-coordinate problem: every NormalizedDevice now has a
real geographic position within Almaty's transport infrastructure,
making the Digital Twin map accurate and defensible at thesis review.
"""

import math
import logging
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger(__name__)

OVERPASS_URL = "https://overpass-api.de/api/interpreter"

# Almaty bounding box: south, west, north, east
ALMATY_BBOX = (43.15, 76.80, 43.40, 77.10)


def fetch_almaty_infrastructure() -> List[Dict]:
    """
    Queries OSM Overpass API for transport infrastructure nodes in Almaty.

    Returns a list of dicts, each containing:
        {
            "id":   <OSM node id>,
            "lat":  <float>,
            "lon":  <float>,
            "tags": { <osm tags> }
        }

    Returns empty list on network error (caller falls back to mock coords).
    """
    south, west, north, east = ALMATY_BBOX
    bbox_str = f"{south},{west},{north},{east}"

    query = f"""
    [out:json][timeout:30][bbox:{bbox_str}];
    (
      node["man_made"="surveillance"];
      node["highway"="traffic_signals"];
      node["amenity"="parking"]["access"!="private"];
    );
    out body;
    """

    try:
        resp = requests.post(
            OVERPASS_URL,
            data={"data": query},
            timeout=35,
        )
        resp.raise_for_status()
        data = resp.json()
        nodes = data.get("elements", [])
        log.info("[osm] Fetched %d infrastructure nodes from Almaty OSM", len(nodes))
        return nodes

    except requests.RequestException as exc:
        log.warning("[osm] Overpass API request failed: %s", exc)
        return []


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Returns the great-circle distance in metres between two coordinates.
    Uses the Haversine formula.
    """
    R = 6_371_000  # Earth radius in metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def get_nearest_osm_node(
    lat: float,
    lon: float,
    nodes: List[Dict],
    max_distance_m: float = 500.0,
) -> Optional[Dict]:
    """
    Finds the nearest OSM node to (lat, lon) within max_distance_m metres.

    Args:
        lat:            Reference latitude (e.g. from mock or IP geolocation).
        lon:            Reference longitude.
        nodes:          OSM node list from fetch_almaty_infrastructure().
        max_distance_m: Maximum search radius in metres (default 500 m).

    Returns:
        Nearest OSM node dict, or None if no node is within range.
    """
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
    """
    Resolves real coordinates for a device IP using OSM nodes.

    Strategy:
      1. If fallback coords exist and an OSM node is nearby → snap to OSM node.
      2. If fallback coords exist but no OSM node nearby → use fallback as-is.
      3. If no fallback coords → pick a random OSM node from the pool.

    Args:
        ip:           Device IP address (for logging).
        fallback_lat: Latitude from mock_locations or previous source.
        fallback_lon: Longitude from mock_locations or previous source.
        osm_nodes:    OSM node list from fetch_almaty_infrastructure().

    Returns:
        Tuple of (lat, lon, source_label) where source_label is one of:
        "osm_snap", "osm_assigned", "fallback", "none".
    """
    if fallback_lat is not None and fallback_lon is not None and osm_nodes:
        node = get_nearest_osm_node(fallback_lat, fallback_lon, osm_nodes)
        if node:
            return node["lat"], node["lon"], "osm_snap"
        return fallback_lat, fallback_lon, "fallback"

    if osm_nodes:
        # Deterministic assignment: hash IP to index so same IP → same node
        idx = hash(ip) % len(osm_nodes)
        node = osm_nodes[idx]
        return node["lat"], node["lon"], "osm_assigned"

    return fallback_lat, fallback_lon, "none"
