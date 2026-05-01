from typing import List
from models import OSINTRecord

def deduplicate(records: List[OSINTRecord]) -> List[OSINTRecord]:
    """Объединить дубли по entity_id, мержить атрибуты"""
    unique: dict = {}
    for rec in records:
        key = f"{rec.entity_type}:{rec.entity_id}"
        if key not in unique:
            unique[key] = rec
        else:
            existing = unique[key]
            existing.attributes.update(rec.attributes)
            existing.tags = list(set(existing.tags + rec.tags))
            existing.cve_ids = list(set(existing.cve_ids + rec.cve_ids))
            existing.confidence = max(existing.confidence, rec.confidence)
    return list(unique.values())
