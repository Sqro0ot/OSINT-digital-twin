from sqlalchemy import Column, BigInteger, Integer, String, Numeric, JSON, TIMESTAMP, Text, Float
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.sql import func
from .db import Base


class RawCensys(Base):
    __tablename__ = "raw_censys"
    
    id = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    ip = Column(INET)
    city = Column(Text)
    country = Column(Text)
    latitude = Column(Float)
    longitude = Column(Float)
    data = Column(JSONB, nullable=False)


class RawCVE(Base):
    __tablename__ = "raw_cve"
    
    id = Column(BigInteger, primary_key=True, index=True)
    fetched_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    cve_id = Column(Text, nullable=False)
    vendor = Column(Text)
    product = Column(Text)
    cvss_score = Column(Numeric)
    data = Column(JSONB, nullable=False)


class NormalizedDevice(Base):
    __tablename__ = "normalized_device"
    
    id = Column(BigInteger, primary_key=True, index=True)
    ip = Column(INET)
    vendor = Column(Text)
    model = Column(Text)
    lat = Column(Float)
    lon = Column(Float)
    risk_level = Column(Text)
    cvss_max = Column(Numeric)
    vulnerabilities = Column(JSONB)
    exposed_ports = Column(JSONB)
    source_refs = Column(JSONB)
    last_updated = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now(), nullable=False)


class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(BigInteger, primary_key=True, index=True)
    type = Column(Text, nullable=False)
    name = Column(Text)
    lat = Column(Float)
    lon = Column(Float)
    props = Column(JSONB, nullable=False, default={}, server_default='{}')
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now(), nullable=False)
