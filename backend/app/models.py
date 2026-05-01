from sqlalchemy import (
    Column,
    BigInteger,
    Integer,
    String,
    Numeric,
    JSON,
    TIMESTAMP,
    Text,
    Float,
)
from sqlalchemy.sql import func
from .db import Base


class RawShodan(Base):
    """
    Сырой JSON-ответ Shodan api.host(ip).
    Заполняется модулем osint_shodan.fetch_shodan_cameras().
    """
    __tablename__ = "raw_shodan"

    id         = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    ip        = Column(String, index=True, unique=True)
    city      = Column(Text)
    country   = Column(Text)
    latitude  = Column(Float)
    longitude = Column(Float)

    # Полный JSON-ответ Shodan (data[], vulns{}, tags[], location{} и т.д.)
    data = Column(JSON, nullable=False)


class RawCVE(Base):
    """
    Сырые данные об уязвимостях (CVE) из внешних источников (NVD, CVEDB и т.п.).
    """
    __tablename__ = "raw_cve"

    id         = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    cve_id     = Column(Text, nullable=False, index=True)
    vendor     = Column(Text, index=True)
    product    = Column(Text, index=True)
    cvss_score = Column(Numeric)

    data = Column(JSON, nullable=False)


class NormalizedDevice(Base):
    """
    Нормализованное представление уязвимого устройства для цифрового двойника.
    Собирает данные из RawShodan, RawCVE, GeoIP и других источников.
    """
    __tablename__ = "normalized_device"

    id = Column(BigInteger, primary_key=True, index=True)

    ip      = Column(String, index=True)
    vendor  = Column(Text)
    model   = Column(Text)

    lat     = Column(Float)
    lon     = Column(Float)
    city    = Column(Text)
    country = Column(Text)

    risk_level      = Column(Text)     # LOW / MEDIUM / HIGH / CRITICAL
    cvss_max        = Column(Numeric)
    confidence      = Column(Float)

    vulnerabilities = Column(JSON)     # список CVE с оценками
    exposed_ports   = Column(JSON)     # список открытых портов
    source_refs     = Column(JSON)     # {"raw_shodan_ids": [...], "raw_cve_ids": [...]}

    created_at   = Column(TIMESTAMP, server_default=func.now(), index=True)
    last_updated = Column(
        TIMESTAMP,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )


class Asset(Base):
    """
    Цифровой двойник актива (камера, контроллер, узловое устройство).
    """
    __tablename__ = "assets"

    id   = Column(BigInteger, primary_key=True, index=True)
    type = Column(Text, nullable=False, index=True)  # camera / controller / gateway
    name = Column(Text)
    lat  = Column(Float)
    lon  = Column(Float)

    # {
    #   "street": "...", "risk_level": "...", "cvss_max": 9.8,
    #   "vendor": "...", "model": "...", "ip": "1.2.3.4",
    #   "exposed_ports": [...], "vulnerabilities": [...],
    #   "confidence": 0.85, "last_seen": "...", "history": [...]
    # }
    props = Column(JSON, nullable=False, default={})

    created_at = Column(TIMESTAMP, server_default=func.now(), index=True)
    updated_at = Column(
        TIMESTAMP,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )


class Alert(Base):
    """
    Алерты на основе изменений OSINT / высокого риска.
    """
    __tablename__ = "alerts"

    id       = Column(BigInteger, primary_key=True, index=True)
    asset_id = Column(BigInteger, index=True)
    severity = Column(Text, index=True)   # HIGH / CRITICAL
    type     = Column(Text)               # NEW_CVE / HIGH_RISK_DEVICE
    message  = Column(Text)
    details  = Column(JSON)

    created_at = Column(TIMESTAMP, server_default=func.now(), index=True)
