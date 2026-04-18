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
from .censys_client import discover_kz_devices
from .epss_client import fetch_epss_scores, enrich_vulns_with_epss, compute_epss_max

router = APIRouter()


# --- OSINT pipeline ---


@router.post("/osint/shodan/fetch")
def trigger_shodan_fetch(
    ips: List[str] = Query(..., description="IP list for Shodan InternetDB lookup"),
    db: Session = Depends(get_db),
):
    """
    Layer 1 — manually trigger Shodan InternetDB enrichment for a list of IPs.
    For automated discovery use POST /osint/censys/discover first.
    """
    n = fetch_shodan_cameras(db, ips=ips)
    return {"fetched": n}


@router.post("/osint/censys/discover")
def trigger_censys_discover():
    """
    Layer 0 — trigger Censys Search API discovery for KZ IoT/camera devices.

    Returns a list of discovered IPs that can be passed to
    POST /osint/shodan/fetch for enrichment.

    Requires CENSYS_PAT to be set in .env.
    Falls back to an empty list when the token is absent or the API
    returns no results.

    Rate limit: Censys free tier supports 250 queries/month.
    """
    ips = discover_kz_devices()
    return {
        "discovered": len(ips),
        "ips": ips,
        "note": "Pass these IPs to POST /osint/shodan/fetch to enrich them.",
    }


@router.post("/osint/epss/enrich")
def trigger_epss_enrich(db: Session = Depends(get_db)):
    """
    Layer 1b — bulk-enrich all NormalizedDevice records with EPSS scores.

    For each device that has at least one CVE, fetches exploitation
    probability from the FIRST EPSS API and writes ``epss_score`` into
    each vulnerability dict.  Also computes ``epss_max`` and updates
    the corresponding Asset props so the dashboard shows it immediately.

    This endpoint is idempotent: re-running it refreshes the scores
    to the latest FIRST EPSS daily release.

    Returns:
        enriched_devices  — number of NormalizedDevice records updated.
        updated_assets    — number of Asset props refreshed.
        cves_enriched     — total number of CVE-EPSS pairs written.
    """
    devices: List[NormalizedDevice] = db.query(NormalizedDevice).all()

    # Collect all CVE IDs across all devices for a single bulk EPSS call
    all_cve_ids: List[str] = []
    for dev in devices:
        for v in (dev.vulnerabilities or []):
            cve_id = v.get("cve_id") if isinstance(v, dict) else None
            if cve_id:
                all_cve_ids.append(cve_id)

    epss_map = fetch_epss_scores(all_cve_ids)  # single API call

    enriched_devices = 0
    cves_enriched = 0

    for dev in devices:
        if not dev.vulnerabilities:
            continue
        enriched = enrich_vulns_with_epss(dev.vulnerabilities, epss_map)
        cves_enriched += sum(
            1 for v in enriched if isinstance(v.get("epss_score"), float)
        )
        dev.vulnerabilities = enriched
        flag_modified(dev, "vulnerabilities")
        enriched_devices += 1

    db.commit()

    # Refresh Asset props with updated epss_max
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
    severity: Optional[str] = None,
    alert_type: Optional[str] = Query(None, alias="type"),
    db: Session = Depends(get_db),
):
    """
    Returns recent alerts, optionally filtered by severity and/or type.

    Supported alert types:
      HIGH_RISK_DEVICE | NEW_CVE | HIGH_EPSS_SCORE | EXPOSED_CRITICAL_PORT | ZERO_DAY_DETECTED
    """
    q = db.query(Alert).order_by(Alert.created_at.desc())
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    if alert_type:
        q = q.filter(Alert.type == alert_type.upper())
    alerts: List[Alert] = q.limit(limit).all()
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


@router.get("/analytics/epss-top")
def get_top_epss(limit: int = 10, db: Session = Depends(get_db)):
    """
    Returns CVEs with the highest EPSS exploitation probability
    across all tracked devices.

    Response fields per item:
      cve_id     — CVE identifier
      epss_score — probability of exploitation (0.0 – 1.0)
      device_count — number of assets affected
    """
    assets = db.query(Asset).filter(Asset.type == "camera").all()
    epss_index: dict = {}  # cve_id -> {epss_score, device_count}
    for a in assets:
        vulns = (a.props or {}).get("vulnerabilities") or []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve_id = v.get("cve_id")
            epss = v.get("epss_score")
            if cve_id and isinstance(epss, (int, float)):
                entry = epss_index.get(cve_id)
                if entry is None:
                    epss_index[cve_id] = {"epss_score": epss, "device_count": 1}
                else:
                    entry["epss_score"] = max(entry["epss_score"], epss)
                    entry["device_count"] += 1
    sorted_epss = sorted(
        epss_index.items(), key=lambda x: x[1]["epss_score"], reverse=True
    )[:limit]
    return [
        {
            "cve_id": cve_id,
            "epss_score": round(data["epss_score"], 4),
            "device_count": data["device_count"],
        }
        for cve_id, data in sorted_epss
    ]


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
                "epss_score": 0.97,
                "description": "ZERO-DAY SIMULATION: Remote Code Execution in Traffic Camera Firmware",
            })
        props["vulnerabilities"] = vulns
        props["cvss_max"] = 10.0
        props["epss_max"] = 0.97
        props["risk_level"] = "CRITICAL"
        asset.props = props
        flag_modified(asset, "props")
        alert = Alert(
            asset_id=asset.id,
            severity="CRITICAL",
            type="ZERO_DAY_DETECTED",
            message=f"Zero-day CVE-2026-9999 detected on {asset.name or asset.id}",
            details={
                "new_cves": ["CVE-2026-9999"],
                "ip": props.get("ip", "unknown"),
                "epss_score": 0.97,
            },
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
            epss_scores = [
                v["epss_score"]
                for v in (original.vulnerabilities or [])
                if isinstance(v.get("epss_score"), (int, float))
            ]
            props["epss_max"] = round(max(epss_scores), 4) if epss_scores else None
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
                epss_scores = [
                    v["epss_score"]
                    for v in vulns
                    if isinstance(v.get("epss_score"), (int, float))
                ]
                props["epss_max"] = round(max(epss_scores), 4) if epss_scores else None
            else:
                props["cvss_max"] = 0
                props["risk_level"] = "LOW"
                props["epss_max"] = None
        asset.props = props
        flag_modified(asset, "props")
        reset_count += 1
    db.commit()
    return {"status": "success", "reset_count": reset_count}


# --- Admin API ---


@router.post("/admin/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    deleted = db.query(Alert).delete(synchronize_session=False)
    db.commit()
    return {"status": "success", "deleted_alerts": deleted}


@router.post("/admin/assets/clear")
def clear_assets(
    confirm: str = Query("", description="Pass confirm=DELETE"),
    asset_type: str = Query("camera"),
    db: Session = Depends(get_db),
):
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
    db.query(Alert).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.type == "camera").delete(synchronize_session=False)
    db.commit()
    synced = sync_devices_to_assets(db)
    return {
        "status": "success",
        "synced_cameras": synced,
        "message": f"Rebuilt {synced} cameras from NormalizedDevice",
    }
