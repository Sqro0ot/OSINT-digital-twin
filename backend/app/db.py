from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables and apply any missing DB-level constraints.
    Called once on startup from main.py.
    """
    from . import models  # noqa: F401 — registers all ORM models
    Base.metadata.create_all(bind=engine)

    # Unique partial index on assets.props->>'ip' for type='camera'.
    # Prevents duplicate assets per IP at the DB level.
    # CREATE INDEX IF NOT EXISTS is idempotent — safe to run on every startup.
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uix_assets_camera_ip
            ON assets ((props->>'ip'))
            WHERE type = 'camera';
        """))
        # Also ensure NormalizedDevice unique constraint exists
        # (safe no-op if already present from models)
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uix_normalized_device_ip
            ON normalized_device (ip);
        """))
        conn.commit()
