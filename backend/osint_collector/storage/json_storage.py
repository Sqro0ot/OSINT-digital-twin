import json
import os
from typing import List
from models import OSINTRecord
from config import config
from datetime import datetime

def save(records: List[OSINTRecord]):
    os.makedirs(config.STORAGE_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(config.STORAGE_DIR, f"osint_{timestamp}.json")

    data = [r.to_dict() for r in records]
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[Storage] Сохранено {len(records)} записей -> {filepath}")
    return filepath

def load_latest() -> List[dict]:
    if not os.path.exists(config.STORAGE_DIR):
        return []
    files = sorted([
        f for f in os.listdir(config.STORAGE_DIR) if f.endswith(".json")
    ])
    if not files:
        return []
    with open(os.path.join(config.STORAGE_DIR, files[-1])) as f:
        return json.load(f)
