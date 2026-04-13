# app/twin.py
"""
Digital Twin synchronisation module (Layer 3 — Integration Layer).

This module bridges the OSINT normalisation pipeline with the Digital Twin
asset model.  It takes ``NormalizedDevice`` records produced by
``normalize.py`` and creates or updates ``Asset`` records that represent
the cyber-physical state of each traffic camera in the Almaty prototype.

Prototype scope
---------------
CAMERA_LIMIT = 3 constrains the prototype to **3 cameras** for the diploma
demonstration.  This matches the 3 mock coordinate pairs initially populated
into ``mock_locations.py`` for the selected district in Almaty.  The limit
exists purely to keep the demo manageable and focused; removing it (or
increasing it) requires no architectural changes — only populating
more target IPs in ``scheduler.TARGET_IPS`` and more coordinates in
``mock_locations.FREE_COORDS``.

Alert generation
-----------------
Two alert types are raised automatically during sync:

- ``HIGH_RISK_DEVICE`` — device risk level is HIGH or CRITICAL.
- ``NEW_CVE``          — one or more CVE IDs appeared that were absent in
  the previous sync cycle (delta detection).

Both types are stored in the ``alerts`` table and surfaced through
``GET /alerts/recent``.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy import cast, String, func
from sqlalchemy.orm import Session

from .models import NormalizedDevice, Asset, Alert
from .risk import cvss_to_level

# Количество камер в прототипе (для диплома: 3 камеры в Алматы).
# Ограничение выбрано для сфокусированной демонстрации полного цикла работы
# платформы. Основание: достаточно для валидации всех модулей
# (OSINT → нормализация → twin → alert → дашборд).
# Для расширения: увеличьте константу и добавьте IP в scheduler.TARGET_IPS.
CAMERA_LIMIT = 3


def _pick_location(dev: NormalizedDevice, idx: int) -> Dict[str, Any]:
    """Возвращает геолокацию из NormalizedDevice.

    В прототипе координаты задаются из mock_locations.FREE_COORDS,
    т.к. InternetDB не возвращает геолокацию. В production-режиме
    используется GeoLite2-City.mmdb (предусмотрен в infra/),
    которая заменяет mock-координаты реальными геоданными.
    """
    return {
        "lat": dev.lat,
        "lon": dev.lon,
        "street": getattr(dev, "city", None) or "Unknown street",
    }


def _build_history_entry(dev: NormalizedDevice) -> Dict[str, Any]:
    """Формирует запись истории для хранения в Asset.props["history"].

    История ограничена последними 50 записями (FIFO)
    для избежания бесконечного роста JSON-поля.
    """
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
    """Генерирует алерты при высоком риске или появлении новых CVE.

    Типы алертов:

    - ``HIGH_RISK_DEVICE`` — вызывается, если risk_level в HIGH или CRITICAL.
    - ``NEW_CVE`` — вызывается, если появились CVE, которых не было
      в предыдущем цикле синхронизации (дельта-детекция).
    """
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
    """Синхронизирует нормализованные устройства с цифровым двойником.

    Алгоритм:
    1. Извлекает последние NormalizedDevice для каждого уникального IP
       (субзапрос GROUP BY ip, MAX(id)), ограничен по CAMERA_LIMIT.
    2. Для каждого устройства: создаёт или обновляет Asset.
    3. Добавляет запись в историю (FIFO, макс. 50 записей).
    4. Генерирует алерты при необходимости.

    Args:
        db:    Сессия SQLAlchemy.
        limit: Максимальное число устройств для обработки (не превышает CAMERA_LIMIT).

    Returns:
        Количество синхронизированных активов.
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
        .limit(CAMERA_LIMIT)  # Прототип: ограничение 3 камеры
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
        history = history[-50:]  # FIFO: храним последние 50 состояний

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
