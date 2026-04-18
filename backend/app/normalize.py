# app/normalize.py

from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from .models import RawCensys, RawCVE, NormalizedDevice
from .mock_locations import FREE_COORDS
from .epss_client import fetch_epss_scores, enrich_vulns_with_epss, compute_epss_max
from .osm_client import fetch_almaty_infrastructure, resolve_coordinates


# -------- OSM nodes cache (loaded once per normalization run) --------

_osm_nodes_cache: Optional[List[Dict]] = None


def _get_osm_nodes() -> List[Dict]:
    """
    Returns OSM infrastructure nodes for Almaty, cached for the
    duration of the current normalization run.
    Falls back to empty list if Overpass API is unavailable.
    """
    global _osm_nodes_cache
    if _osm_nodes_cache is None:
        _osm_nodes_cache = fetch_almaty_infrastructure()
    return _osm_nodes_cache


def reset_osm_cache() -> None:
    """Clears the OSM node cache. Call between normalization runs."""
    global _osm_nodes_cache
    _osm_nodes_cache = None


# -------- Внутреннее состояние для раздачи координат (fallback) --------

assigned_coords: Dict[str, Tuple[float, float]] = {}
free_index: int = 0


def get_coords_for_ip(ip: str, raw: RawCensys) -> Tuple[Optional[float], Optional[float]]:
    """
    Resolves coordinates for a device IP.

    Priority:
      1. OSM Overpass API — snaps to nearest real infrastructure node.
      2. mock_locations.FREE_COORDS — fallback if OSM unavailable.
      3. raw.latitude / raw.longitude — last resort.
    """
    global free_index

    # 1) Try OSM-based resolution
    osm_nodes = _get_osm_nodes()
    if osm_nodes:
        # Use mock coords as initial reference if available
        fallback_lat: Optional[float] = None
        fallback_lon: Optional[float] = None

        if ip in assigned_coords:
            fallback_lat, fallback_lon = assigned_coords[ip]
        elif free_index < len(FREE_COORDS):
            fallback_lat, fallback_lon = FREE_COORDS[free_index]

        lat, lon, source = resolve_coordinates(ip, fallback_lat, fallback_lon, osm_nodes)
        if lat is not None and lon is not None:
            assigned_coords[ip] = (lat, lon)
            return lat, lon

    # 2) Fallback: mock_locations pool
    if ip in assigned_coords:
        return assigned_coords[ip]

    if free_index < len(FREE_COORDS):
        lat, lon = FREE_COORDS[free_index]
        free_index += 1
        assigned_coords[ip] = (lat, lon)
        return lat, lon

    # 3) Last resort: raw record values
    return raw.latitude, raw.longitude


# -------- Вспомогательные функции --------


def derive_vendor_model_from_services(services) -> (Optional[str], Optional[str]):
    title_str = ""
    vendor: Optional[str] = None
    model: Optional[str] = None

    for svc in services or []:
        product = (svc.get("product") or "").lower()
        title_str += " " + product

        http = svc.get("http") or {}
        title = (http.get("title") or "").lower()
        title_str += " " + title

    if "hikvision" in title_str:
        vendor = "Hikvision"
    elif "dahua" in title_str:
        vendor = "Dahua"

    return vendor, model


def cvss_to_risk_level(cvss_max: Optional[float]) -> str:
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


def compute_confidence(
    source_score: float,
    freshness_score: float,
    confirmation_score: float,
    completeness_score: float,
    epss_max: Optional[float] = None,
) -> float:
    """
    Weighted confidence score for a normalized device record.

    Weights (sum = 1.0):
      w1 = 0.30  source reliability
      w2 = 0.20  data freshness
      w3 = 0.20  cross-source confirmation
      w4 = 0.15  record completeness
      w5 = 0.15  exploitation probability (EPSS) — new dimension

    When epss_max is None (EPSS unavailable), w5 is redistributed
    proportionally across the other four weights, preserving the
    original 0.35/0.25/0.20/0.20 ratio from the thesis formula.
    """
    if epss_max is not None:
        w1, w2, w3, w4, w5 = 0.30, 0.20, 0.20, 0.15, 0.15
        return (
            w1 * source_score
            + w2 * freshness_score
            + w3 * confirmation_score
            + w4 * completeness_score
            + w5 * epss_max
        )
    else:
        # Original weights when EPSS is unavailable
        w1, w2, w3, w4 = 0.35, 0.25, 0.20, 0.20
        return (
            w1 * source_score
            + w2 * freshness_score
            + w3 * confirmation_score
            + w4 * completeness_score
        )


def find_cve_by_ids(db: Session, cve_ids: List[str]) -> Dict[str, RawCVE]:
    if not cve_ids:
        return {}
    rows = (
        db.query(RawCVE)
        .filter(RawCVE.cve_id.in_(cve_ids))
        .all()
    )
    return {row.cve_id: row for row in rows}


def find_cve_for_vendor(db: Session, vendor: Optional[str]) -> List[Dict]:
    if not vendor:
        return []
    q = db.query(RawCVE).filter(RawCVE.vendor.ilike(f"%{vendor}%"))
    vulns: List[Dict] = []
    for row in q.all():
        vulns.append(
            {
                "cve_id": row.cve_id,
                "cvss_score": float(row.cvss_score)
                if row.cvss_score is not None
                else None,
                "description": row.data.get("description") if row.data else None,
                "source": "vendor_match",
            }
        )
    return vulns


def compute_cvss_max_from_vulns(vulns: List[Dict]) -> Optional[float]:
    scores = [
        float(v["cvss_score"])
        for v in vulns
        if v.get("cvss_score") is not None
    ]
    return max(scores) if scores else None


# -------- Основной пайплайн нормализации --------


def normalize_shodan_hosts(db: Session, batch_size: int = 200) -> int:
    raw_hosts: List[RawCensys] = (
        db.query(RawCensys)
        .order_by(RawCensys.id)
        .limit(batch_size)
        .all()
    )

    # Reset OSM cache at the start of each normalization run
    reset_osm_cache()

    # Pre-collect all CVE IDs in this batch for bulk EPSS fetch
    all_cve_ids: List[str] = []
    for raw in raw_hosts:
        host = raw.data or {}
        vuln_ids = host.get("vulns") or []
        if isinstance(vuln_ids, list):
            all_cve_ids.extend(str(v) for v in vuln_ids)

    # Bulk fetch EPSS scores for all CVEs in batch (single API call)
    epss_map: Dict[str, float] = fetch_epss_scores(all_cve_ids)

    count = 0

    for raw in raw_hosts:
        host = raw.data or {}

        # 1) IP
        ip = host.get("ip") or host.get("ip_str") or raw.ip
        if not ip:
            continue

        # 2) Сервисы / порты
        services = host.get("data") or host.get("services") or []
        if isinstance(services, dict):
            services = [services]

        if not services and "ports" in host:
            ports = host.get("ports") or []
            services = [
                {"port": p, "product": None, "transport": "tcp"} for p in ports
            ]

        vendor, model = derive_vendor_model_from_services(services)

        # 3) Уязвимости
        vulns: List[Dict] = []

        host_vuln_ids: List[str] = []
        if isinstance(host.get("vulns"), list):
            host_vuln_ids = [str(v) for v in host.get("vulns")]

        cve_map = find_cve_by_ids(db, host_vuln_ids)
        for cve_id in host_vuln_ids:
            row = cve_map.get(cve_id)
            vulns.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": float(row.cvss_score)
                    if row and row.cvss_score is not None
                    else None,
                    "description": row.data.get("description") if row and row.data else None,
                    "source": "internetdb",
                }
            )

        vulns.extend(find_cve_for_vendor(db, vendor))

        # 3b) Enrich vulnerabilities with EPSS scores
        vulns = enrich_vulns_with_epss(vulns, epss_map)
        epss_max: Optional[float] = compute_epss_max(vulns)

        cvss_max: Optional[float] = compute_cvss_max_from_vulns(vulns)
        risk_level: str = cvss_to_risk_level(cvss_max)

        # 4) Geo — OSM-based resolution with mock fallback
        lat, lon = get_coords_for_ip(ip, raw)
        city = raw.city
        country = raw.country

        # 5) exposed_ports
        exposed_ports: List[Dict] = []
        for svc in services:
            exposed_ports.append(
                {
                    "port": svc.get("port"),
                    "service_name": svc.get("product"),
                    "transport_protocol": svc.get("transport")
                    or svc.get("transport_protocol"),
                }
            )

        # 6) Confidence — now includes EPSS as 5th dimension
        source_score = 0.9
        freshness_score = 1.0

        has_internetdb_cve = any(v.get("source") == "internetdb" for v in vulns)
        has_vendor_cve = any(v.get("source") == "vendor_match" for v in vulns)
        if has_internetdb_cve and has_vendor_cve:
            confirmation_score = 1.0
        elif has_internetdb_cve or has_vendor_cve:
            confirmation_score = 0.7
        else:
            confirmation_score = 0.3

        completeness_score = 0.0
        if ip:
            completeness_score += 0.4
        if exposed_ports:
            completeness_score += 0.3
        if vulns:
            completeness_score += 0.3

        confidence = compute_confidence(
            source_score,
            freshness_score,
            confirmation_score,
            completeness_score,
            epss_max=epss_max,
        )

        dev = NormalizedDevice(
            ip=ip,
            vendor=vendor,
            model=model,
            lat=lat,
            lon=lon,
            city=city,
            country=country,
            risk_level=risk_level,
            cvss_max=cvss_max,
            confidence=confidence,
            vulnerabilities=vulns,
            exposed_ports=exposed_ports,
            source_refs={
                "raw_shodan_ids": [raw.id],
                "epss_enriched": epss_max is not None,
                "geo_source": "osm" if _osm_nodes_cache else "mock",
            },
        )

        db.add(dev)
        count += 1

    db.commit()
    return count
