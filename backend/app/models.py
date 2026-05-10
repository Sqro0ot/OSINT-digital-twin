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
    UniqueConstraint,
    Index,
)
from sqlalchemy.sql import func
from .db import Base


class RawShodan(Base):
    """
    Raw JSON response from Shodan InternetDB.
    One record per IP (unique constraint enforced).
    """
    __tablename__ = "raw_shodan"

    id         = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), index=True)

    ip        = Column(String, index=True, unique=True, nullable=False)
    city      = Column(Text)
    country   = Column(Text)
    latitude  = Column(Float)
    longitude = Column(Float)

    data = Column(JSON, nullable=False)


class RawCVE(Base):
    """
    Raw CVE data from external sources (NVD, CVEDB, etc.).
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
    Normalized device representation for the digital twin.
    Strictly ONE record per IP (unique constraint on ip column).
    """
    __tablename__ = "normalized_device"
    __table_args__ = (
        UniqueConstraint("ip", name="uq_normalized_device_ip"),
    )

    id = Column(BigInteger, primary_key=True, index=True)

    ip      = Column(String, index=True, nullable=False)
    vendor  = Column(Text)
    model   = Column(Text)

    lat     = Column(Float)
    lon     = Column(Float)
    city    = Column(Text)
    country = Column(Text)

    risk_level      = Column(Text)     # LOW / MEDIUM / HIGH / CRITICAL
    cvss_max        = Column(Numeric)
    confidence      = Column(Float)

    vulnerabilities = Column(JSON)
    exposed_ports   = Column(JSON)
    source_refs     = Column(JSON)

    created_at   = Column(TIMESTAMP, server_default=func.now(), index=True)
    last_updated = Column(
        TIMESTAMP,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )


class Asset(Base):
    """
    Digital twin asset (camera, controller, gateway).
    One asset per IP: enforced via unique partial index on props->>'ip'.
    """
    __tablename__ = "assets"

    id   = Column(BigInteger, primary_key=True, index=True)
    type = Column(Text, nullable=False, index=True)
    name = Column(Text)
    lat  = Column(Float)
    lon  = Column(Float)

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
    Alerts based on OSINT changes / high risk.
    """
    __tablename__ = "alerts"

    id       = Column(BigInteger, primary_key=True, index=True)
    asset_id = Column(BigInteger, index=True)
    severity = Column(Text, index=True)
    type     = Column(Text)
    message  = Column(Text)
    details  = Column(JSON)

    created_at = Column(TIMESTAMP, server_default=func.now(), index=True)
