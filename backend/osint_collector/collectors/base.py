from abc import ABC, abstractmethod
from typing import List
import logging

logger = logging.getLogger(__name__)

class BaseCollector(ABC):
    source_name: str = "base"

    def run(self, query: str) -> List:
        """Полный цикл: получить -> нормализовать -> вернуть"""
        records = []
        try:
            raw_items = self.fetch(query)
            logger.info(f"[{self.source_name}] Получено {len(raw_items)} записей по запросу: {query}")
            for item in raw_items:
                try:
                    record = self.normalize(item)
                    records.append(record)
                except Exception as e:
                    logger.warning(f"[{self.source_name}] Ошибка нормализации: {e}")
        except Exception as e:
            logger.error(f"[{self.source_name}] Ошибка сбора данных: {e}")
        return records

    @abstractmethod
    def fetch(self, query: str) -> List[dict]:
        """Получить сырые данные из источника"""
        pass

    @abstractmethod
    def normalize(self, raw_item: dict):
        """Привести к единой модели OSINTRecord"""
        pass
