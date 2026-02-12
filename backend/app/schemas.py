from pydantic import BaseModel
from typing import Any, Dict, List, Optional


from typing import Optional

class CameraBase(BaseModel):
    id: int
    lat: float | None = None
    lon: float | None = None
    risk_level: str | None = None
    name: str | None = None
    vulnerabilities: list[dict] | None = None
    cvss_max: float | None = None
    confidence: float | None = None
    last_seen: str | None = None



class CameraDetail(CameraBase):
    props: Dict[str, Any]


class StatsSummary(BaseModel):
    total_devices: int
    by_risk: Dict[str, int]
    avg_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
