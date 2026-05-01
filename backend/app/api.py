from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, String
from sqlalchemy.orm.attributes import flag_modified
import re

from .db import get_db
from .osint_shodan import fetch_shodan_cameras
from .normalize import normalize_shodan_hosts
from .twin import sync_devices_to_assets
from .models import Asset, NormalizedDevice, Alert, RawCVE
from .schemas import CameraBase, CameraDetail, StatsSummary
from .epss_client import fetch_epss_scores, enrich_vulns_with_epss, compute_epss_max

router = APIRouter()


# ---------------------------------------------------------------------------
# OSINT pipeline helpers
# ---------------------------------------------------------------------------


@router.post("/osint/shodan/fetch")
def trigger_shodan_fetch(
    ips: List[str] = Query(..., description="IP list for Shodan InternetDB lookup"),
    db: Session = Depends(get_db),
):
    n = fetch_shodan_cameras(db, ips=ips)
    return {"fetched": n}


@router.post("/osint/epss/enrich")
def trigger_epss_enrich(db: Session = Depends(get_db)):
    devices: List[NormalizedDevice] = db.query(NormalizedDevice).all()

    all_cve_ids: List[str] = []
    for dev in devices:
        for v in (dev.vulnerabilities or []):
            cve_id = v.get("cve_id") if isinstance(v, dict) else None
            if cve_id:
                all_cve_ids.append(cve_id)

    epss_map = fetch_epss_scores(all_cve_ids)
    enriched_devices = 0
    cves_enriched = 0

    for dev in devices:
        if not dev.vulnerabilities:
            continue
        enriched = enrich_vulns_with_epss(dev.vulnerabilities, epss_map)
        cves_enriched += sum(1 for v in enriched if isinstance(v.get("epss_score"), float))
        dev.vulnerabilities = enriched
        flag_modified(dev, "vulnerabilities")
        enriched_devices += 1

    db.commit()

    updated_assets = 0
    assets: List[Asset] = db.query(Asset).filter(Asset.type == "camera").all()
    for asset in assets:
        asset_ip = (asset.props or {}).get("ip")
        if not asset_ip:
            continue
        dev = (
            db.query(NormalizedDevice)
            .filter(NormalizedDevice.ip == asset_ip)
            .order_by(NormalizedDevice.id.desc())
            .first()
        )
        if dev is None:
            continue
        epss_max = compute_epss_max(dev.vulnerabilities or [])
        if epss_max is not None:
            props = dict(asset.props or {})
            props["epss_max"] = round(epss_max, 4)
            props["vulnerabilities"] = dev.vulnerabilities
            asset.props = props
            flag_modified(asset, "props")
            updated_assets += 1

    db.commit()
    return {
        "enriched_devices": enriched_devices,
        "updated_assets": updated_assets,
        "cves_enriched": cves_enriched,
        "epss_scores_available": len(epss_map),
    }


def _run_epss_enrich_for_ip(ip: str, db: Session) -> None:
    dev: Optional[NormalizedDevice] = (
        db.query(NormalizedDevice)
        .filter(NormalizedDevice.ip == ip)
        .order_by(NormalizedDevice.id.desc())
        .first()
    )
    if dev is None or not dev.vulnerabilities:
        return

    cve_ids = [
        v["cve_id"] for v in dev.vulnerabilities
        if isinstance(v, dict) and v.get("cve_id")
    ]
    if not cve_ids:
        return

    epss_map = fetch_epss_scores(cve_ids)
    if not epss_map:
        return

    dev.vulnerabilities = enrich_vulns_with_epss(dev.vulnerabilities, epss_map)
    flag_modified(dev, "vulnerabilities")
    db.commit()

    asset: Optional[Asset] = (
        db.query(Asset)
        .filter(Asset.type == "camera", cast(Asset.props["ip"], String) == ip)
        .order_by(Asset.id.desc())
        .first()
    )
    if asset:
        epss_max = compute_epss_max(dev.vulnerabilities)
        props = dict(asset.props or {})
        props["epss_max"] = round(epss_max, 4) if epss_max is not None else None
        props["vulnerabilities"] = dev.vulnerabilities
        asset.props = props
        flag_modified(asset, "props")
        db.commit()


@router.post("/osint/normalize")
def trigger_normalize(db: Session = Depends(get_db)):
    n = normalize_shodan_hosts(db)
    return {"normalized": n}


@router.post("/twin/sync")
def trigger_twin_sync(db: Session = Depends(get_db)):
    n = sync_devices_to_assets(db)
    return {"synced": n}


# ---------------------------------------------------------------------------
# Add device by IP — full pipeline
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


@router.post("/devices/add")
def add_device_by_ip(
    ip: str = Query(..., description="IPv4 address to add"),
    db: Session = Depends(get_db),
):
    ip = ip.strip()
    if not _IP_RE.match(ip):
        raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {ip!r}")

    fetched = fetch_shodan_cameras(db, ips=[ip])
    normalize_shodan_hosts(db)
    _run_epss_enrich_for_ip(ip, db)
    sync_devices_to_assets(db)
    db.commit()

    asset: Optional[Asset] = (
        db.query(Asset)
        .filter(Asset.type == "camera", cast(Asset.props["ip"], String) == ip)
        .order_by(Asset.id.desc())
        .first()
    )
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=(
                "Asset not created \u2014 IP may have no open ports in InternetDB, "
                f"or CAMERA_LIMIT reached (fetched_raw={fetched})"
            ),
        )

    props = asset.props or {}
    return {
        "status": "ok",
        "asset_id": asset.id,
        "ip": ip,
        "risk_level": props.get("risk_level", "UNKNOWN"),
        "lat": float(asset.lat) if asset.lat is not None else None,
        "lon": float(asset.lon) if asset.lon is not None else None,
        "cvss_max": props.get("cvss_max"),
        "epss_max": props.get("epss_max"),
        "vendor": props.get("vendor"),
        "vulnerabilities_count": len(props.get("vulnerabilities") or []),
    }


# ---------------------------------------------------------------------------
# CVE Management
# ---------------------------------------------------------------------------


@router.post("/cve/backfill")
def backfill_cvss(db: Session = Depends(get_db)):
    from .nvd_client import backfill_rawcve_scores
    backfill_rawcve_scores(db, api_key=None, batch_size=50)
    return {"status": "ok", "message": "CVSS backfill completed"}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts/recent")
def get_recent_alerts(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    alerts = (
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
            "alert_type": a.type,   # alias for frontend compatibility
            "message": a.message,
            "details": a.details,
            "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
        }
        for a in alerts
    ]


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


@router.get("/analytics/risk-distribution")
def get_risk_distribution(db: Session = Depends(get_db)):
    """
    Returns [{name: 'CRITICAL', value: 3}, ...] for pie chart.
    """
    rows = (
        db.query(
            cast(Asset.props["risk_level"], String).label("risk_level"),
            func.count().label("cnt"),
        )
        .filter(Asset.type == "camera")
        .group_by(cast(Asset.props["risk_level"], String))
        .all()
    )
    return [{"name": r.risk_level or "UNKNOWN", "value": r.cnt} for r in rows]


@router.get("/analytics/top-cves")
def get_top_cves(
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """
    Top CVEs by frequency across all camera assets.
    Returns [{cve_id, count}].
    """
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    cve_counter: dict = {}
    for asset in assets:
        for vuln in (asset.props or {}).get("vulnerabilities") or []:
            cve_id = vuln.get("cve_id") if isinstance(vuln, dict) else None
            if cve_id:
                cve_counter[cve_id] = cve_counter.get(cve_id, 0) + 1

    top = sorted(cve_counter.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"cve_id": cve_id, "count": count} for cve_id, count in top]


@router.get("/analytics/epss-top")
def get_epss_top(
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """
    Top CVEs by max EPSS score across all camera assets.
    Returns [{cve_id, epss_score}].
    """
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    epss_map: dict = {}
    for asset in assets:
        for vuln in (asset.props or {}).get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cve_id = vuln.get("cve_id")
            score = vuln.get("epss_score")
            if cve_id and isinstance(score, (int, float)):
                if cve_id not in epss_map or score > epss_map[cve_id]:
                    epss_map[cve_id] = score

    top = sorted(epss_map.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"cve_id": cve_id, "epss_score": score} for cve_id, score in top]


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@router.post("/admin/assets/clear")
def clear_assets(
    confirm: str = Query(""),
    asset_type: str = Query("camera"),
    db: Session = Depends(get_db),
):
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Pass confirm=DELETE to proceed")
    deleted_assets = db.query(Asset).filter(Asset.type == asset_type).delete(synchronize_session=False)
    deleted_alerts = db.query(Alert).delete(synchronize_session=False)
    db.commit()
    return {"status": "success", "deleted_assets": deleted_assets, "deleted_alerts": deleted_alerts}


@router.post("/admin/assets/rebuild")
def rebuild_assets(db: Session = Depends(get_db)):
    db.query(Asset).filter(Asset.type == "camera").delete(synchronize_session=False)
    db.query(Alert).delete(synchronize_session=False)
    db.commit()
    synced = sync_devices_to_assets(db)
    return {"status": "success", "synced": synced}


# ---------------------------------------------------------------------------
# Simulate
# ---------------------------------------------------------------------------


@router.post("/simulate/zero-day")
def simulate_zero_day(db: Session = Depends(get_db)):
    import random
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    if not assets:
        return {"status": "error", "message": "No cameras to simulate"}

    targets = random.sample(assets, min(3, len(assets)))
    for asset in targets:
        props = dict(asset.props or {})
        props["risk_level"] = "CRITICAL"
        props["cvss_max"] = 9.8
        asset.props = props
        flag_modified(asset, "props")
        db.add(Alert(
            asset_id=asset.id,
            severity="CRITICAL",
            type="ZERO_DAY_DETECTED",
            message=f"Zero-day simulation triggered on {asset.name}",
            details={"simulated": True, "ip": (asset.props or {}).get("ip")},
        ))
    db.commit()
    return {"status": "success", "affected": len(targets)}


@router.post("/simulate/reset")
def simulate_reset(db: Session = Depends(get_db)):
    db.query(Alert).filter(Alert.type == "ZERO_DAY_DETECTED").delete(synchronize_session=False)
    db.commit()
    synced = sync_devices_to_assets(db)
    return {"status": "success", "synced": synced}


# ---------------------------------------------------------------------------
# REST API cameras map
# ---------------------------------------------------------------------------


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
        cameras.append(
            CameraBase(
                id=a.id,
                lat=float(a.lat) if a.lat is not None else None,
                lon=float(a.lon) if a.lon is not None else None,
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
        db.query(
            cast(Asset.props["risk_level"], String).label("risk_level"),
            func.count().label("cnt"),
        )
        .filter(Asset.type == "camera")
        .group_by(cast(Asset.props["risk_level"], String))
        .all()
    )
    by_risk = {r.risk_level: r.cnt for r in rows}
    critical = by_risk.get("CRITICAL", 0)
    high = by_risk.get("HIGH", 0)

    last_sync_asset = (
        db.query(Asset)
        .filter(Asset.type == "camera")
        .order_by(Asset.id.desc())
        .first()
    )
    last_sync = (last_sync_asset.props or {}).get("last_seen") if last_sync_asset else None

    return StatsSummary(
        total_devices=total_devices,
        critical=critical,
        high=high,
        by_risk=by_risk,
        last_sync=last_sync,
    )
