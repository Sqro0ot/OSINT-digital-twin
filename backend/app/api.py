from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, String

from .db import get_db
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets
from .models import Asset, NormalizedDevice, Alert, RawCensys, RawCVE
from .schemas import CameraBase, CameraDetail, StatsSummary

router = APIRouter()


# --- OSINT-пайплайн на Shodan ---


@router.post("/osint/shodan/fetch")
def trigger_shodan_fetch(
    ips: List[str] = Query(..., description="Список IP для lookup в Shodan"),
    db: Session = Depends(get_db),
):
    n = fetch_shodan_cameras(db, ips=ips)
    return {"fetched": n}


@router.post("/osint/normalize")
def trigger_normalize(db: Session = Depends(get_db)):
    n = normalize_shodan_hosts(db)
    return {"normalized": n}


@router.post("/twin/sync")
def trigger_twin_sync(db: Session = Depends(get_db)):
    n = sync_devices_to_assets(db)
    return {"synced": n}


# --- CVE Management ---


@router.post("/cve/populate")
def populate_cve_from_censys(db: Session = Depends(get_db)):
    """
    Берёт все CVE из raw_censys.data['vulns'] и создаёт пустые записи в raw_cve,
    если их ещё нет.
    """
    hosts = db.query(RawCensys).all()
    cve_ids = set()
    
    for host in hosts:
        vulns = (host.data or {}).get("vulns") or []
        if isinstance(vulns, list):
            cve_ids.update(str(v) for v in vulns)
    
    count = 0
    for cve_id in cve_ids:
        exists = db.query(RawCVE).filter(RawCVE.cve_id == cve_id).first()
        if not exists:
            row = RawCVE(cve_id=cve_id, vendor=None, product=None, cvss_score=None, data={})
            db.add(row)
            count += 1
    
    db.commit()
    return {"created_cve_records": count}


@router.post("/cve/backfill")
def backfill_cvss(db: Session = Depends(get_db)):
    """
    Для всех CVE без cvss_score загружает данные из NVD и обновляет БД.
    Внимание: может занять несколько минут в зависимости от количества CVE.
    """
    from .nvd_client import backfill_rawcve_scores
    
    backfill_rawcve_scores(db, api_key=None, batch_size=50)
    return {"status": "ok", "message": "CVSS backfill completed"}


# --- REST API цифрового двойника камер ---


@router.get("/map/cameras", response_model=List[CameraBase])
def get_cameras(
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Asset).filter(Asset.type == "camera")
    if risk_level:
        q = q.filter(cast(Asset.props["risk_level"], String) == risk_level)

    assets = q.all()
    cameras: List[CameraBase] = []
    for a in assets:
        props = a.props or {}

        lat = float(a.lat) if a.lat is not None else None
        lon = float(a.lon) if a.lon is not None else None

        cameras.append(
            CameraBase(
                id=a.id,
                lat=lat,
                lon=lon,
                risk_level=props.get("risk_level"),
                name=a.name,
                vulnerabilities=props.get("vulnerabilities"),
                cvss_max=props.get("cvss_max"),
                confidence=props.get("confidence"),
                last_seen=props.get("last_seen"),
            )
        )
    return cameras


@router.get("/assets/{asset_id}", response_model=CameraDetail)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Not found")
    return CameraDetail(
        id=a.id,
        lat=a.lat,
        lon=a.lon,
        risk_level=(a.props or {}).get("risk_level"),
        name=a.name,
        props=a.props or {},
    )


@router.get("/stats/summary", response_model=StatsSummary)
def get_summary(db: Session = Depends(get_db)):
    total_devices = db.query(Asset).filter(Asset.type == "camera").count()

    rows = (
        db.query(cast(Asset.props["risk_level"], String).label("risk"), func.count())
        .filter(Asset.type == "camera")
        .group_by("risk")
        .all()
    )
    by_risk = {row.risk or "unknown": row[1] for row in rows}

    avg_cvss, max_cvss = db.query(
        func.avg(NormalizedDevice.cvss_max),
        func.max(NormalizedDevice.cvss_max),
    ).one()

    return StatsSummary(
        total_devices=total_devices,
        by_risk=by_risk,
        avg_cvss=avg_cvss,
        max_cvss=max_cvss,
    )


# --- Alerts API ---


@router.get("/alerts/recent")
def get_recent_alerts(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """
    Возвращает последние алерты по камерам.
    """
    alerts: List[Alert] = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": a.id,
            "asset_id": a.asset_id,
            "severity": a.severity,
            "type": a.type,
            "message": a.message,
            "details": a.details,
            "created_at": a.created_at.isoformat() + "Z",
        }
        for a in alerts
    ]
