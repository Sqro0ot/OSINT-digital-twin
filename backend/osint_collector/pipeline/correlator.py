from models import OSINTRecord
from typing import Optional

# Ключевые слова -> подсистема Smart City
SUBSYSTEM_KEYWORDS = {
    "traffic": [
        "traffic", "camera", "hikvision", "dahua", "axis",
        "rtsp", "cctv", "crossroad", "intersection"
    ],
    "energy": [
        "scada", "modbus", "dnp3", "iec104", "energy",
        "substation", "smartgrid", "meter", "bacnet"
    ],
    "water": [
        "water", "pump", "valve", "plc", "irrigation",
        "sewage", "reservoir"
    ],
    "public_safety": [
        "police", "emergency", "fire", "alarm",
        "access control", "rfid", "biometric"
    ],
}

def detect_subsystem(record: OSINTRecord) -> Optional[str]:
    text = " ".join([
        str(record.attributes.get("product", "")),
        str(record.attributes.get("banner", "")),
        str(record.attributes.get("description", "")),
        " ".join(record.tags),
    ]).lower()

    for subsystem, keywords in SUBSYSTEM_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return subsystem
    return None

def correlate(records: list) -> list:
    for record in records:
        if record.subsystem is None:
            record.subsystem = detect_subsystem(record)
    return records
