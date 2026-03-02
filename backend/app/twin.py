# app/twin.py

from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy import cast, String, func
from sqlalchemy.orm import Session

from .models import NormalizedDevice, Asset, Alert
from .risk import cvss_to_level

# Количество камер в прототипе (для диплома: 3 камеры в Алматы)
CAMERA_LIMIT = 3


def _pick_location(dev: NormalizedDevice, idx: int) -> Dict[str, Any]:
    """
    Берём координаты напрямую из NormalizedDevice.
    """
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


def _maybe_create_alert(
    db: Session,
    asset: Asset,
    dev: NormalizedDevice,
    previous_vulns: Optional[List[Dict[str, Any]]],
) -> None:
    if dev.risk_level in ("HIGH", "CRITICAL"):
        alert = Alert(
            asset_id=asset.id,
            severity=dev.risk_level,
            type="HIGH_RISK_DEVICE",
            message=f"Device {asset.name} has risk level {dev.risk_level}",
            details={
                "ip": dev.ip,
                "cvss_max": float(dev.cvss_max) if dev.cvss_max is not None else None,
            },
        )
        db.add(alert)

    current_ids = {
        v.get("cve_id") for v in (dev.vulnerabilities or []) if v.get("cve_id")
    }
    prev_ids = {
        v.get("cve_id") for v in (previous_vulns or []) if v.get("cve_id")
    }

    new_ids = current_ids - prev_ids
    if new_ids:
        if dev.cvss_max is not None:
            severity = cvss_to_level(dev.cvss_max)
        else:
            severity = "MEDIUM"

        if dev.cvss_max is None and len(new_ids) >= 20:
            severity = "HIGH"

        alert = Alert(
            asset_id=asset.id,
            severity=severity,
            type="NEW_CVE",
            message=f"New vulnerabilities for {asset.name}: {', '.join(sorted(new_ids))}",
            details={
                "ip": dev.ip,
                "new_cves": sorted(new_ids),
            },
        )
        db.add(alert)


def sync_devices_to_assets(db: Session, limit: int = 200) -> int:
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
        .limit(CAMERA_LIMIT)  # Ограничиваем количество камер
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

        asset.props = {
            "street": loc["street"],
            "risk_level": dev.risk_level,
            "cvss_max": float(dev.cvss_max) if dev.cvss_max is not None else None,
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
        _maybe_create_alert(db, asset, dev, prev_vulns)

        count += 1

    db.commit()
    return count
