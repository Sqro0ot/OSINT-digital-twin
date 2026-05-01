# app/twin.py
"""
Digital Twin synchronisation module (Layer 3 — Integration Layer).

Bridges the OSINT normalisation pipeline with the Digital Twin asset model.
Takes NormalizedDevice records and creates/updates Asset records.

CAMERA_LIMIT = 50 supports up to 50 devices (расширено для demo).
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy import cast, String, func
from sqlalchemy.orm import Session

from .models import NormalizedDevice, Asset, Alert
from .risk import cvss_to_level

CAMERA_LIMIT = 50  # увеличено с 15 → 50

CRITICAL_PORTS = {21, 22, 23, 80, 554, 8000, 8080, 8443, 9000}
EPSS_ALERT_THRESHOLD = 0.7


def _pick_location(dev: NormalizedDevice, idx: int) -> Dict[str, Any]:
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


def _maybe_create_alerts(
    db: Session,
    asset: Asset,
    dev: NormalizedDevice,
    previous_vulns: Optional[List[Dict[str, Any]]],
) -> None:
    # 1. HIGH_RISK_DEVICE
    if dev.risk_level in ("HIGH", "CRITICAL"):
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

    # 2. NEW_CVE
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

    # 3. HIGH_EPSS_SCORE
    high_epss_vulns = [
        v for v in (dev.vulnerabilities or [])
        if isinstance(v.get("epss_score"), (int, float))
        and v["epss_score"] >= EPSS_ALERT_THRESHOLD
    ]
    if high_epss_vulns:
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

    # 4. EXPOSED_CRITICAL_PORT
    if dev.risk_level not in ("LOW", "UNKNOWN"):
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
    Синхронизирует NormalizedDevice → Asset (digital twin).

    Выбирает последнюю запись по каждому уникальному IP (GROUP BY ip, MAX(id)).
    Лимит: CAMERA_LIMIT (50) устройств.
    """
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

    for idx, dev in enumerate(devices):
        if not dev.ip:
            continue

        loc = _pick_location(dev, idx)

        asset: Optional[Asset] = (
            db.query(Asset)
            .filter(
                Asset.type == "camera",
                cast(Asset.props["ip"], String) == dev.ip,
            )
            .one_or_none()
        )

        if asset is None:
            asset = Asset(type="camera")
            db.add(asset)

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
        }

        db.flush()
        _maybe_create_alerts(db, asset, dev, prev_vulns)

        count += 1

    db.commit()
    return count
