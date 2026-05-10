# app/normalize.py

from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from .models import RawShodan, RawCVE, NormalizedDevice
from .mock_locations import FREE_COORDS
from .epss_client import fetch_epss_scores, enrich_vulns_with_epss, compute_epss_max
from .osm_client import fetch_almaty_infrastructure, resolve_coordinates
from .greynoise_client import bulk_lookup, parse_classification, extract_tags
from .config import settings


# -------- OSM nodes cache (per-process, reset each normalize call) --------

_osm_nodes_cache: Optional[List[Dict]] = None


def _get_osm_nodes() -> List[Dict]:
    global _osm_nodes_cache
    if _osm_nodes_cache is None:
        _osm_nodes_cache = fetch_almaty_infrastructure()
    return _osm_nodes_cache


def reset_osm_cache() -> None:
    global _osm_nodes_cache
    _osm_nodes_cache = None


# -------- Координаты через hash(ip) --------


def get_coords_for_ip(ip: str) -> Tuple[float, float]:
    osm_nodes = _get_osm_nodes()
    mock_idx = hash(ip) % len(FREE_COORDS)
    fallback_lat, fallback_lon = FREE_COORDS[mock_idx]
    lat, lon, _ = resolve_coordinates(ip, fallback_lat, fallback_lon, osm_nodes)
    return lat, lon


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


def cvss_to_risk_level(cvss_max: Optional[float], gn_classification: str = "unknown") -> str:
    """
    Risk level with GreyNoise adjustment.
    - malicious: floor raised to HIGH
    - noise (scanner): CRITICAL/HIGH downgraded to MEDIUM
    - benign: no change (known CDN, still can be vulnerable)
    """
    if gn_classification == "malicious":
        if cvss_max is None or cvss_max < 7.0:
            return "HIGH"
        if cvss_max >= 9.0:
            return "CRITICAL"
        return "HIGH"

    if cvss_max is None:
        base = "UNKNOWN"
    elif cvss_max >= 9.0:
        base = "CRITICAL"
    elif cvss_max >= 7.0:
        base = "HIGH"
    elif cvss_max >= 4.0:
        base = "MEDIUM"
    elif cvss_max > 0.0:
        base = "LOW"
    else:
        base = "UNKNOWN"

    if gn_classification == "noise" and base in ("CRITICAL", "HIGH"):
        return "MEDIUM"

    return base


def compute_confidence(
    source_score: float,
    freshness_score: float,
    confirmation_score: float,
    completeness_score: float,
    epss_max: Optional[float] = None,
    gn_classification: str = "unknown",
) -> float:
    if epss_max is not None:
        w1, w2, w3, w4, w5 = 0.30, 0.20, 0.20, 0.15, 0.15
        base = w1*source_score + w2*freshness_score + w3*confirmation_score + w4*completeness_score + w5*epss_max
    else:
        w1, w2, w3, w4 = 0.35, 0.25, 0.20, 0.20
        base = w1*source_score + w2*freshness_score + w3*confirmation_score + w4*completeness_score

    if gn_classification == "malicious":
        base = min(1.0, base + 0.15)
    elif gn_classification == "noise":
        base = max(0.0, base - 0.10)
    elif gn_classification == "benign":
        base = max(0.0, base - 0.05)

    return round(base, 4)


def find_cve_by_ids(db: Session, cve_ids: List[str]) -> Dict[str, RawCVE]:
    if not cve_ids:
        return {}
    rows = db.query(RawCVE).filter(RawCVE.cve_id.in_(cve_ids)).all()
    return {row.cve_id: row for row in rows}


def find_cve_for_vendor(db: Session, vendor: Optional[str]) -> List[Dict]:
    if not vendor:
        return []
    vulns: List[Dict] = []
    for row in db.query(RawCVE).filter(RawCVE.vendor.ilike(f"%{vendor}%")).all():
        vulns.append({
            "cve_id": row.cve_id,
            "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
            "description": row.data.get("description") if row.data else None,
            "source": "vendor_match",
        })
    return vulns


def compute_cvss_max_from_vulns(vulns: List[Dict]) -> Optional[float]:
    scores = [float(v["cvss_score"]) for v in vulns if v.get("cvss_score") is not None]
    return max(scores) if scores else None


# -------- Основной пайплайн нормализации --------


def normalize_shodan_hosts(db: Session, batch_size: int = 200) -> int:
    """
    Upsert NormalizedDevice from RawShodan.
    One NormalizedDevice per unique IP — no duplicates.
    GreyNoise enrichment applied if GREYNOISE_API_KEY is set.
    """
    # Deduplicate raw_shodan: take latest record per IP
    subq = (
        db.query(
            RawShodan.ip.label("ip"),
            func.max(RawShodan.id).label("max_id"),
        )
        .group_by(RawShodan.ip)
        .subquery()
    )
    raw_hosts: List[RawShodan] = (
        db.query(RawShodan)
        .join(subq, (RawShodan.ip == subq.c.ip) & (RawShodan.id == subq.c.max_id))
        .order_by(RawShodan.id)
        .limit(batch_size)
        .all()
    )

    if not raw_hosts:
        return 0

    reset_osm_cache()

    # Bulk EPSS fetch
    all_cve_ids: List[str] = []
    for raw in raw_hosts:
        vuln_ids = (raw.data or {}).get("vulns") or []
        if isinstance(vuln_ids, list):
            all_cve_ids.extend(str(v) for v in vuln_ids)
    epss_map: Dict[str, float] = fetch_epss_scores(all_cve_ids)

    # Bulk GreyNoise lookup (no-op stub if no API key)
    all_ips = [raw.ip for raw in raw_hosts if raw.ip]
    gn_map: Dict[str, Dict] = bulk_lookup(all_ips, api_key=settings.GREYNOISE_API_KEY)

    count = 0

    for raw in raw_hosts:
        host = raw.data or {}
        ip = host.get("ip") or host.get("ip_str") or raw.ip
        if not ip:
            continue

        # UPSERT: strict one record per IP
        existing_devs: List[NormalizedDevice] = (
            db.query(NormalizedDevice)
            .filter(NormalizedDevice.ip == ip)
            .order_by(NormalizedDevice.id)
            .all()
        )
        # Remove duplicates, keep the oldest
        if len(existing_devs) > 1:
            for dup in existing_devs[1:]:
                db.delete(dup)
        existing_dev: Optional[NormalizedDevice] = existing_devs[0] if existing_devs else None

        services = host.get("data") or host.get("services") or []
        if isinstance(services, dict):
            services = [services]
        if not services and "ports" in host:
            services = [{"port": p, "product": None, "transport": "tcp"} for p in (host.get("ports") or [])]

        vendor, model = derive_vendor_model_from_services(services)

        vulns: List[Dict] = []
        host_vuln_ids = [str(v) for v in (host.get("vulns") or []) if isinstance(host.get("vulns"), list)]
        cve_map = find_cve_by_ids(db, host_vuln_ids)
        for cve_id in host_vuln_ids:
            row = cve_map.get(cve_id)
            vulns.append({
                "cve_id": cve_id,
                "cvss_score": float(row.cvss_score) if row and row.cvss_score is not None else None,
                "description": row.data.get("description") if row and row.data else None,
                "source": "internetdb",
            })
        vulns.extend(find_cve_for_vendor(db, vendor))
        vulns = enrich_vulns_with_epss(vulns, epss_map)
        epss_max: Optional[float] = compute_epss_max(vulns)
        cvss_max: Optional[float] = compute_cvss_max_from_vulns(vulns)

        # GreyNoise enrichment
        gn_data = gn_map.get(ip) or {}
        gn_classification = parse_classification(gn_data)
        gn_tags = extract_tags(gn_data)
        gn_name = gn_data.get("name")
        gn_noise = gn_data.get("noise", False)
        gn_riot = gn_data.get("riot", False)
        gn_message = gn_data.get("message", "")

        risk_level: str = cvss_to_risk_level(cvss_max, gn_classification)
        lat, lon = get_coords_for_ip(ip)

        exposed_ports: List[Dict] = [{
            "port": svc.get("port"),
            "service_name": svc.get("product"),
            "transport_protocol": svc.get("transport") or svc.get("transport_protocol"),
        } for svc in services]

        source_score, freshness_score = 0.9, 1.0
        has_internetdb_cve = any(v.get("source") == "internetdb" for v in vulns)
        has_vendor_cve = any(v.get("source") == "vendor_match" for v in vulns)
        confirmation_score = (
            1.0 if (has_internetdb_cve and has_vendor_cve)
            else (0.7 if (has_internetdb_cve or has_vendor_cve) else 0.3)
        )
        completeness_score = (
            (0.4 if ip else 0.0) +
            (0.3 if exposed_ports else 0.0) +
            (0.3 if vulns else 0.0)
        )
        confidence = compute_confidence(
            source_score, freshness_score, confirmation_score, completeness_score,
            epss_max=epss_max, gn_classification=gn_classification,
        )

        source_refs = {
            "raw_shodan_ids": [raw.id],
            "epss_enriched": epss_max is not None,
            "geo_source": "osm_hash" if _osm_nodes_cache else "mock_hash",
            "greynoise": {
                "classification": gn_classification,
                "noise": gn_noise,
                "riot": gn_riot,
                "name": gn_name,
                "tags": gn_tags,
                "message": gn_message,
            },
        }

        if existing_dev:
            existing_dev.vendor = vendor
            existing_dev.model = model
            existing_dev.lat = lat
            existing_dev.lon = lon
            existing_dev.risk_level = risk_level
            existing_dev.cvss_max = cvss_max
            existing_dev.confidence = confidence
            existing_dev.vulnerabilities = vulns
            existing_dev.exposed_ports = exposed_ports
            existing_dev.source_refs = source_refs
        else:
            db.add(NormalizedDevice(
                ip=ip, vendor=vendor, model=model,
                lat=lat, lon=lon, city=raw.city, country=raw.country,
                risk_level=risk_level, cvss_max=cvss_max, confidence=confidence,
                vulnerabilities=vulns, exposed_ports=exposed_ports,
                source_refs=source_refs,
            ))
        count += 1

    db.commit()
    return count
