from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Подключение к БД
    DATABASE_URL: str

    # Ключ для Shodan (как в документации: SHODAN_API_KEY)
    SHODAN_API_KEY: str

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
