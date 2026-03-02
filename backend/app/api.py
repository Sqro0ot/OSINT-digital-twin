from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, String
from sqlalchemy.orm.attributes import flag_modified

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


# --- Analytics API ---


@router.get("/analytics/risk-distribution")
def get_risk_distribution(db: Session = Depends(get_db)):
    rows = (
        db.query(
            cast(Asset.props["risk_level"], String).label("name"),
            func.count().label("value"),
        )
        .filter(Asset.type == "camera")
        .group_by(cast(Asset.props["risk_level"], String))
        .all()
    )
    return [
        {
            "name": row.name.strip('"') if row.name else "UNKNOWN",
            "value": row.value,
        }
        for row in rows
    ]


@router.get("/analytics/top-cves")
def get_top_cves(limit: int = 5, db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    cve_counter: dict = {}
    for a in assets:
        vulns = (a.props or {}).get("vulnerabilities") or []
        for v in vulns:
            cve_id = v.get("cve_id") if isinstance(v, dict) else str(v)
            if cve_id:
                cve_counter[cve_id] = cve_counter.get(cve_id, 0) + 1
    sorted_cves = sorted(cve_counter.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"cve_id": cve_id, "count": count} for cve_id, count in sorted_cves]


# --- Simulation API ---


@router.post("/simulate/zero-day")
def simulate_zero_day(db: Session = Depends(get_db)):
    targets = db.query(Asset).filter(Asset.type == "camera").all()
    non_critical = [
        a for a in targets
        if (a.props or {}).get("risk_level") != "CRITICAL"
    ][:5]
    if not non_critical:
        non_critical = targets[:5]
    if not non_critical:
        return {"status": "error", "message": "No cameras found in database"}
    for asset in non_critical:
        props = dict(asset.props or {})
        vulns = list(props.get("vulnerabilities") or [])
        if not any(v.get("cve_id") == "CVE-2026-9999" for v in vulns if isinstance(v, dict)):
            vulns.append({
                "cve_id": "CVE-2026-9999",
                "cvss_score": 10.0,
                "description": "ZERO-DAY SIMULATION: Remote Code Execution in Traffic Camera Firmware",
            })
        props["vulnerabilities"] = vulns
        props["cvss_max"] = 10.0
        props["risk_level"] = "CRITICAL"
        asset.props = props
        flag_modified(asset, "props")
        alert = Alert(
            asset_id=asset.id,
            severity="CRITICAL",
            type="ZERO_DAY_DETECTED",
            message=f"Zero-day CVE-2026-9999 detected on {asset.name or asset.id}",
            details={"new_cves": ["CVE-2026-9999"], "ip": props.get("ip", "unknown")},
        )
        db.add(alert)
    db.commit()
    return {"status": "success", "infected_count": len(non_critical)}


@router.post("/simulate/reset")
def simulate_reset(db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    reset_count = 0
    for asset in assets:
        props = dict(asset.props or {})
        asset_ip = props.get("ip")
        original: Optional[NormalizedDevice] = None
        if asset_ip:
            original = (
                db.query(NormalizedDevice)
                .filter(NormalizedDevice.ip == asset_ip)
                .order_by(NormalizedDevice.id.desc())
                .first()
            )
        if original:
            props["vulnerabilities"] = original.vulnerabilities or []
            props["cvss_max"] = float(original.cvss_max) if original.cvss_max is not None else None
            props["risk_level"] = original.risk_level or "LOW"
        else:
            vulns = [
                v for v in (props.get("vulnerabilities") or [])
                if isinstance(v, dict) and v.get("cve_id") != "CVE-2026-9999"
            ]
            props["vulnerabilities"] = vulns
            if vulns:
                max_score = max((v.get("cvss_score") or 0) for v in vulns)
                props["cvss_max"] = max_score
                props["risk_level"] = (
                    "CRITICAL" if max_score >= 9.0 else
                    "HIGH" if max_score >= 7.0 else
                    "MEDIUM" if max_score >= 4.0 else "LOW"
                )
            else:
                props["cvss_max"] = 0
                props["risk_level"] = "LOW"
        asset.props = props
        flag_modified(asset, "props")
        reset_count += 1
    db.commit()
    return {"status": "success", "reset_count": reset_count}


# --- Admin API ---


@router.post("/admin/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    """
    Удаляет все алерты. Активы (камеры) не трогает.
    """
    deleted = db.query(Alert).delete(synchronize_session=False)
    db.commit()
    return {"status": "success", "deleted_alerts": deleted}


@router.post("/admin/assets/clear")
def clear_assets(
    confirm: str = Query("", description="Передайте confirm=DELETE"),
    asset_type: str = Query("camera"),
    db: Session = Depends(get_db),
):
    """
    Очищает активы + алерты. Требует confirm=DELETE.
    """
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Pass ?confirm=DELETE")
    deleted_alerts = db.query(Alert).delete(synchronize_session=False)
    deleted_assets = (
        db.query(Asset).filter(Asset.type == asset_type).delete(synchronize_session=False)
    )
    db.commit()
    return {
        "status": "success",
        "deleted_assets": deleted_assets,
        "deleted_alerts": deleted_alerts,
        "hint": "Call POST /twin/sync to restore cameras",
    }


@router.post("/admin/assets/rebuild")
def rebuild_assets(db: Session = Depends(get_db)):
    """
    Очищает все активы + алерты и сразу пересоздаёт их из NormalizedDevice.
    """
    db.query(Alert).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.type == "camera").delete(synchronize_session=False)
    db.commit()
    synced = sync_devices_to_assets(db)
    return {
        "status": "success",
        "synced_cameras": synced,
        "message": f"Rebuilt {synced} cameras from NormalizedDevice",
    }
