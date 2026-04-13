from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Подключение к БД
    DATABASE_URL: str

    # АУТЕНТИФИКАЦИЯ SHODAN
    # Примечание: в прототипе используется БЕСПЛАТНЫЙ InternetDB API
    # (https://internetdb.shodan.io/{ip}) без ключа. Переменная SHODAN_API_KEY
    # предусмотрена для расширения до полного Shodan API
    # (геолокация, баннеры, история) в production-режиме.
    SHODAN_API_KEY: Optional[str] = None

    # NVD API ключ для получения CVSS-оценок из NVD NIST (nvd_client.py).
    # Без ключа запросы работают, но ограничены (5 запросов/сек vs 50/сек с ключом).
    # Получить бесплатно: https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: Optional[str] = None

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
