from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import uuid

@dataclass
class OSINTRecord:
    """Единая нормализованная модель OSINT-записи"""
    id: str                         = field(default_factory=lambda: str(uuid.uuid4()))
    source: str                     = ""        # shodan / greynoise / cve
    entity_type: str                = ""        # ip / domain / vulnerability
    entity_id: str                  = ""        # IP-адрес, домен, CVE-ID

    # Геоданные
    city: Optional[str]             = None
    country: Optional[str]          = None
    latitude: Optional[float]       = None
    longitude: Optional[float]      = None

    # Технические атрибуты
    attributes: Dict[str, Any]      = field(default_factory=dict)
    tags: List[str]                 = field(default_factory=list)
    cve_ids: List[str]              = field(default_factory=list)

    # Качество и риск
    confidence: float               = 0.5
    risk_score: float               = 0.0

    # Привязка к подсистеме Smart City
    subsystem: Optional[str]        = None      # traffic / energy / water / public_safety

    # Временные метки
    collected_at: str               = field(default_factory=lambda: datetime.utcnow().isoformat())
    first_seen: Optional[str]       = None
    last_seen: Optional[str]        = None

    def to_dict(self) -> dict:
        return self.__dict__
