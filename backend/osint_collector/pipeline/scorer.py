from models import OSINTRecord

# Опасные порты для инфраструктуры умного города
CRITICAL_PORTS = {23, 2323, 3389, 5900, 102, 502, 47808}  # Telnet, RDP, VNC, S7, Modbus, BACnet
HIGH_PORTS     = {80, 8080, 8443, 21, 22}

def calculate_risk(record: OSINTRecord) -> float:
    score = 0.0
    attrs = record.attributes
    tags  = record.tags

    # Источник
    if record.source == "shodan":
        score += 15  # факт экспозиции в интернете

    # Опасный порт
    port = attrs.get("port")
    if port in CRITICAL_PORTS:
        score += 30
    elif port in HIGH_PORTS:
        score += 10

    # GreyNoise классификация
    classification = attrs.get("classification", "")
    if classification == "malicious":
        score += 35
    elif classification == "unknown":
        score += 10

    # Наличие CVE
    score += min(len(record.cve_ids) * 5, 20)

    # Тег noise (активный сканер / зловред)
    if attrs.get("noise") is True:
        score += 10

    # CVSS score (для vulnerability-записей)
    cvss = attrs.get("cvss_score", 0)
    if cvss >= 9.0:
        score += 20
    elif cvss >= 7.0:
        score += 10

    return round(min(score, 100.0), 2)
