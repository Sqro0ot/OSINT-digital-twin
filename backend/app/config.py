from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional

# Resolve .env relative to this file: backend/app/config.py -> backend/ -> project root
_HERE = Path(__file__).resolve().parent          # backend/app/
_BACKEND = _HERE.parent                          # backend/
_ROOT = _BACKEND.parent                          # OSINT-digital-twin/

# Search order: backend/.env -> project root .env
_ENV_FILE = _BACKEND / ".env" if (_BACKEND / ".env").exists() else _ROOT / ".env"


class Settings(BaseSettings):
    # Database connection
    DATABASE_URL: str

    # Censys PAT (Layer 0 — device discovery)
    # Get yours at: https://app.censys.io/account/api
    CENSYS_PAT: Optional[str] = None

    # Shodan API key (optional — InternetDB is used by default, no key needed)
    SHODAN_API_KEY: Optional[str] = None

    # NVD API key (optional — increases rate limit from 5 to 50 req/30s)
    # Register at: https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: Optional[str] = None

    # GreyNoise Community API key (optional — raises daily limit beyond 100 req/day)
    # Register at: https://viz.greynoise.io/signup
    # Without key: 100 IP lookups/day (sufficient for diploma prototype)
    GREYNOISE_API_KEY: Optional[str] = None

    class Config:
        env_file = str(_ENV_FILE)
        extra = "ignore"


settings = Settings()
