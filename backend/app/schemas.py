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


class CameraDetail(CameraBase):
    props: Dict[str, Any]


class StatsSummary(BaseModel):
    total_devices: int
    by_risk: Dict[str, int]
    avg_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
