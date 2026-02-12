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


class RawCensys(Base):
    """
    Сырой технический OSINT по IP (InternetDB / Shodan / Censys и т.п.).
    """
    __tablename__ = "raw_censys"

    id = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    ip = Column(String, index=True)
    city = Column(Text)
    country = Column(Text)
    latitude = Column(Float)
    longitude = Column(Float)

    # Полный JSON-ответ источника (InternetDB, Shodan host и т.п.)
    data = Column(JSON, nullable=False)


class RawCVE(Base):
    """
    Сырые данные об уязвимостях (CVE) из внешних источников (NVD, CVEDB и т.п.).
    """
    __tablename__ = "raw_cve"

    id = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    cve_id = Column(Text, nullable=False, index=True)
    vendor = Column(Text, index=True)
    product = Column(Text, index=True)
    cvss_score = Column(Numeric)

    # Полный JSON-ответ о CVE (описание, метрики CVSS, ссылки и т.п.)
    data = Column(JSON, nullable=False)


class NormalizedDevice(Base):
    """
    Нормализованное представление уязвимого устройства для цифрового двойника.
    Собирает данные из RawCensys, RawCVE, GeoIP и других источников.
    """
    __tablename__ = "normalized_device"

    id = Column(BigInteger, primary_key=True, index=True)

    ip = Column(String, index=True)
    vendor = Column(Text)
    model = Column(Text)

    # Геолокация (из GeoIP или mock)
    lat = Column(Float)
    lon = Column(Float)
    city = Column(Text)
    country = Column(Text)

    # Метрики риска
    risk_level = Column(Text)          # LOW / MEDIUM / HIGH / CRITICAL
    cvss_max = Column(Numeric)         # максимальный CVSS по устройству
    confidence = Column(Float)         # ConfidenceScore, 0..1

    # Структурированные поля
    vulnerabilities = Column(JSON)     # список CVE с оценками и описаниями
    exposed_ports = Column(JSON)       # список открытых портов/сервисов

    # Источники и ссылки на сырые записи
    source_refs = Column(JSON)         # например {"raw_shodan_ids":[...], "raw_cve_ids":[...]}

    created_at = Column(TIMESTAMP, server_default=func.now(), index=True)
    last_updated = Column(
        TIMESTAMP,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )


class Asset(Base):
    """
    Цифровой двойник актива (в прототипе — камера дорожного движения).
    """
    __tablename__ = "assets"

    id = Column(BigInteger, primary_key=True, index=True)

    type = Column(Text, nullable=False, index=True)  # e.g. "camera"
    name = Column(Text)
    lat = Column(Float)
    lon = Column(Float)

    # Произвольные свойства актива:
    # {
    #   "street": "...",
    #   "risk_level": "...",
    #   "cvss_max": 9.8,
    #   "vendor": "...",
    #   "model": "...",
    #   "ip": "1.2.3.4",
    #   "exposed_ports": [...],
    #   "vulnerabilities": [...],
    #   "confidence": 0.85,
    #   "last_seen": "...",
    #   "history": [...]
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
    Алерты, генерируемые на основе изменений OSINT / высокого риска.
    Используется на уровне интеграции (Layer 3) и визуализации (Layer 4).
    """
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, index=True)

    asset_id = Column(BigInteger, index=True)  # ссылка на Asset.id
    severity = Column(Text, index=True)        # e.g. "HIGH", "CRITICAL"
    type = Column(Text)                        # e.g. "NEW_CVE", "HIGH_RISK_DEVICE"
    message = Column(Text)                     # человекочитаемое описание

    created_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    # Дополнительные технические данные (например, список новых CVE)
    details = Column(JSON)
