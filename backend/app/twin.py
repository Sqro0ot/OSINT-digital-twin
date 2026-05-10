# app/twin.py
"""
Digital Twin synchronisation module (Layer 3 — Integration Layer).

Bridges the OSINT normalisation pipeline with the Digital Twin asset model.
Takes NormalizedDevice records and creates/updates Asset records.

CAMERA_LIMIT = 50 supports up to 50 devices.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy import cast, String, func, text
from sqlalchemy.orm import Session

from .models import NormalizedDevice, Asset, Alert
from .risk import cvss_to_level

CAMERA_LIMIT = 50

CRITICAL_PORTS = {21, 22, 23, 80, 554, 8000, 8080, 8443, 9000}
EPSS_ALERT_THRESHOLD = 0.7


def _pick_location(dev: NormalizedDevice) -> Dict[str, Any]:
    return {
        "lat": dev.lat,
        "lon": dev.lon,
        "street": getattr(dev, "city", None) or "Unknown street",
    }


def _build_history_entry(dev: NormalizedDevice) -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": dev.ip,
        "risk_level": dev.risk_level,
        "cvss_max": float(dev.cvss_max) if dev.cvss_max is not None else None,
        "vulnerabilities": dev.vulnerabilities,
        "exposed_ports": dev.exposed_ports,
    }


def _find_asset_by_ip(db: Session, ip: str) -> List["Asset"]:
    """
    Find all camera assets for a given IP.

    Uses ->> (text extraction) instead of cast(props['ip'], String).
    cast() returns JSON-quoted strings like '"1.2.3.4"' which never
    matches the plain string '1.2.3.4', causing false "not found" and
    subsequent UniqueViolation on INSERT.
    """
    return (
        db.query(Asset)
        .filter(
            Asset.type == "camera",
            Asset.props["ip"].as_string() == ip,
        )
        .order_by(Asset.id)
        .all()
    )


def _maybe_create_alerts(
    db: Session,
    asset: Asset,
    dev: NormalizedDevice,
    previous_vulns: Optional[List[Dict[str, Any]]],
    is_new_asset: bool = False,
) -> None:
    """
    Creates alerts for a device. Deduplicates by type+asset_id to avoid
    alert spam on repeated syncs.
    """
    existing_types = {
        a.type for a in db.query(Alert.type)
        .filter(Alert.asset_id == asset.id)
        .all()
    } if not is_new_asset else set()

    # 1. MALICIOUS_IP_DETECTED — GreyNoise says this IP is a known threat actor
    gn = (dev.source_refs or {}).get("greynoise") or {}
    gn_classification = gn.get("classification", "unknown")
    if gn_classification == "malicious" and "MALICIOUS_IP_DETECTED" not in existing_types:
        db.add(Alert(
            asset_id=asset.id,
            severity="CRITICAL",
            type="MALICIOUS_IP_DETECTED",
            message=(
                f"GreyNoise identified {dev.ip} as a malicious host"
                + (f" ({gn.get('name')})" if gn.get("name") else "")
            ),
            details={
                "ip": dev.ip,
                "greynoise_classification": gn_classification,
                "greynoise_name": gn.get("name"),
                "greynoise_tags": gn.get("tags") or [],
                "noise": gn.get("noise", False),
                "riot": gn.get("riot", False),
            },
        ))

    # 2. HIGH_RISK_DEVICE
    if dev.risk_level in ("HIGH", "CRITICAL") and "HIGH_RISK_DEVICE" not in existing_types:
        db.add(Alert(
            asset_id=asset.id,
            severity=dev.risk_level,
            type="HIGH_RISK_DEVICE",
            message=f"Device {asset.name} has risk level {dev.risk_level}",
            details={
                "ip": dev.ip,
                "cvss_max": float(dev.cvss_max) if dev.cvss_max is not None else None,
            },
        ))

    # 3. NEW_CVE — only on actual new CVEs, not on every sync
    current_ids = {
        v.get("cve_id") for v in (dev.vulnerabilities or []) if v.get("cve_id")
    }
    prev_ids = {
        v.get("cve_id") for v in (previous_vulns or []) if v.get("cve_id")
    }
    new_ids = current_ids - prev_ids
    if new_ids:
        severity = cvss_to_level(dev.cvss_max) if dev.cvss_max is not None else "MEDIUM"
        if dev.cvss_max is None and len(new_ids) >= 20:
            severity = "HIGH"
        db.add(Alert(
            asset_id=asset.id,
            severity=severity,
            type="NEW_CVE",
            message=f"New vulnerabilities for {asset.name}: {', '.join(sorted(new_ids))}",
            details={"ip": dev.ip, "new_cves": sorted(new_ids)},
        ))

    # 4. HIGH_EPSS_SCORE
    high_epss_vulns = [
        v for v in (dev.vulnerabilities or [])
        if isinstance(v.get("epss_score"), (int, float))
        and v["epss_score"] >= EPSS_ALERT_THRESHOLD
    ]
    if high_epss_vulns and "HIGH_EPSS_SCORE" not in existing_types:
        max_epss = max(v["epss_score"] for v in high_epss_vulns)
        top_cve = max(high_epss_vulns, key=lambda v: v["epss_score"]).get("cve_id", "unknown")
        db.add(Alert(
            asset_id=asset.id,
            severity="HIGH",
            type="HIGH_EPSS_SCORE",
            message=(
                f"Device {asset.name} has {len(high_epss_vulns)} CVE(s) "
                f"with high exploitation probability (max EPSS: {max_epss:.2f})"
            ),
            details={
                "ip": dev.ip,
                "top_cve": top_cve,
                "max_epss": round(max_epss, 4),
                "affected_cves": [
                    {"cve_id": v.get("cve_id"), "epss_score": v["epss_score"]}
                    for v in high_epss_vulns
                ],
            },
        ))

    # 5. EXPOSED_CRITICAL_PORT
    if dev.risk_level not in ("LOW", "UNKNOWN") and "EXPOSED_CRITICAL_PORT" not in existing_types:
        exposed = [
            p for p in (dev.exposed_ports or [])
            if isinstance(p.get("port"), int) and p["port"] in CRITICAL_PORTS
        ]
        if exposed:
            port_list = sorted({p["port"] for p in exposed})
            db.add(Alert(
                asset_id=asset.id,
                severity="MEDIUM",
                type="EXPOSED_CRITICAL_PORT",
                message=(
                    f"Device {asset.name} exposes critical port(s): "
                    f"{', '.join(str(p) for p in port_list)}"
                ),
                details={
                    "ip": dev.ip,
                    "ports": port_list,
                    "risk_level": dev.risk_level,
                },
            ))


def sync_devices_to_assets(db: Session, limit: int = 200) -> int:
    """
    Sync NormalizedDevice → Asset (digital twin).

    - Selects one record per unique IP (latest by id).
    - Upserts Asset: one Asset per IP, no duplicates.
    - Removes stale duplicate Assets for same IP.
    - CAMERA_LIMIT caps total devices at 50.
    """
    # Expire all cached ORM objects so we read fresh data from DB
    db.expire_all()

    subq = (
        db.query(
            NormalizedDevice.ip.label("ip"),
            func.max(NormalizedDevice.id).label("max_id"),
        )
        .group_by(NormalizedDevice.ip)
        .subquery()
    )

    devices: List[NormalizedDevice] = (
        db.query(NormalizedDevice)
        .join(
            subq,
            (NormalizedDevice.ip == subq.c.ip)
            & (NormalizedDevice.id == subq.c.max_id),
        )
        .order_by(NormalizedDevice.id)
        .limit(CAMERA_LIMIT)
        .all()
    )

    count = 0

    for dev in devices:
        if not dev.ip:
            continue

        loc = _pick_location(dev)

        # Find existing assets using ->> text extraction (not cast which adds quotes)
        existing_assets = _find_asset_by_ip(db, dev.ip)

        # Clean up duplicates — keep the oldest, delete the rest
        if len(existing_assets) > 1:
            for dup in existing_assets[1:]:
                db.query(Alert).filter(Alert.asset_id == dup.id).delete()
                db.delete(dup)
            db.flush()

        is_new_asset = len(existing_assets) == 0
        asset: Asset = existing_assets[0] if existing_assets else Asset(type="camera")
        if is_new_asset:
            db.add(asset)
            db.flush()  # get asset.id before alerts

        prev_vulns = (asset.props or {}).get("vulnerabilities") if asset.props else None

        asset.name = f"{dev.vendor or 'Camera'} {dev.ip}".strip()
        asset.lat = loc["lat"]
        asset.lon = loc["lon"]

        history: List[Dict[str, Any]] = (asset.props or {}).get("history") or []
        history.append(_build_history_entry(dev))
        history = history[-50:]

        epss_scores = [
            v["epss_score"]
            for v in (dev.vulnerabilities or [])
            if isinstance(v.get("epss_score"), (int, float))
        ]
        epss_max = max(epss_scores) if epss_scores else None

        gn = (dev.source_refs or {}).get("greynoise") or {}

        asset.props = {
            "street": loc["street"],
            "risk_level": dev.risk_level,
            "cvss_max": float(dev.cvss_max) if dev.cvss_max is not None else None,
            "epss_max": round(epss_max, 4) if epss_max is not None else None,
            "vendor": dev.vendor,
            "model": dev.model,
            "ip": dev.ip,
            "exposed_ports": dev.exposed_ports,
            "vulnerabilities": dev.vulnerabilities,
            "confidence": float(dev.confidence) if dev.confidence is not None else None,
            "last_seen": datetime.utcnow().isoformat() + "Z",
            "history": history,
            "greynoise": {
                "classification": gn.get("classification", "unknown"),
                "noise": gn.get("noise", False),
                "riot": gn.get("riot", False),
                "name": gn.get("name"),
                "tags": gn.get("tags") or [],
            },
        }

        db.flush()
        _maybe_create_alerts(db, asset, dev, prev_vulns, is_new_asset=is_new_asset)

        count += 1

    db.commit()
    return count
