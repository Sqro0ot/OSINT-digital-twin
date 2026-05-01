import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Config:
    # API ключи
    SHODAN_API_KEY:     str = os.getenv("SHODAN_API_KEY", "")
    GREYNOISE_API_KEY:  str = os.getenv("GREYNOISE_API_KEY", "")

    # Интервалы опроса (секунды)
    INTERVAL_SHODAN:    int = 86400   # раз в сутки
    INTERVAL_GREYNOISE: int = 3600    # раз в час
    INTERVAL_CVE:       int = 3600

    # Поисковые запросы под Алматы / умный город
    SHODAN_QUERIES: list = None

    # Хранилище
    STORAGE_DIR: str = "./storage/data"

    def __post_init__(self):
        if self.SHODAN_QUERIES is None:
            self.SHODAN_QUERIES = [
                'city:"Almaty" port:80,443,8080',
                'city:"Almaty" product:"Hikvision"',
                'city:"Almaty" "traffic controller"',
                'city:"Almaty" "SCADA"',
            ]

config = Config()
