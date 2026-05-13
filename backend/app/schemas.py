from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class CameraBase(BaseModel):
    id: int
    ip: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    risk_level: Optional[str] = None
    name: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    vulnerabilities: Optional[List[dict]] = None
    exposed_ports: Optional[List[dict]] = None
    cvss_max: Optional[float] = None
    confidence: Optional[float] = None
    last_seen: Optional[str] = None
    # full props blob so the frontend can access greynoise, whois, epss_max, etc.
    props: Optional[Dict[str, Any]] = None


class CameraDetail(CameraBase):
    pass  # props already in CameraBase


class StatsSummary(BaseModel):
    total_devices: int
    critical: int = 0
    high: int = 0
    by_risk: Dict[str, int] = {}
    avg_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    last_sync: Optional[str] = None
