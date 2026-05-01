import logging
from collectors.shodan_collector    import ShodanCollector
from collectors.greynoise_collector import GreyNoiseCollector
from collectors.cve_collector       import CVECollector
from pipeline.normalizer            import deduplicate
from pipeline.scorer                import calculate_risk
from pipeline.correlator            import correlate
from storage.json_storage           import save
from twin.twin_updater              import TwinUpdater
from config                         import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def run_pipeline():
    logging.info("=== OSINT Pipeline запущен ===")
    all_records = []

    # 1. Сбор из Shodan
    shodan = ShodanCollector()
    for query in config.SHODAN_QUERIES:
        all_records.extend(shodan.run(query))

    # 2. Обогащение через GreyNoise
    gn = GreyNoiseCollector()
    ip_records = [r for r in all_records if r.entity_type == "ip"]
    for record in ip_records[:20]:  # лимит для прототипа
        gn_results = gn.run(record.entity_id)
        if gn_results:
            gn_rec = gn_results[0]
            record.attributes.update(gn_rec.attributes)
            record.tags = list(set(record.tags + gn_rec.tags))

    # 3. Сбор CVE по ключевым словам
    cve = CVECollector()
    for keyword in ["hikvision", "traffic controller", "SCADA ICS"]:
        all_records.extend(cve.run(keyword))

    logging.info(f"Всего собрано: {len(all_records)} записей")

    # 4. Дедупликация
    records = deduplicate(all_records)
    logging.info(f"После дедупликации: {len(records)} уникальных записей")

    # 5. Скоринг риска
    for record in records:
        record.risk_score = calculate_risk(record)

    # 6. Корреляция с подсистемами Smart City
    records = correlate(records)

    # 7. Вывод топ-10 по риску
    top = sorted(records, key=lambda r: r.risk_score, reverse=True)[:10]
    logging.info("\n=== ТОП-10 по риску ===")
    for r in top:
        logging.info(
            f"  [{r.risk_score:5.1f}] {r.entity_id:<18} "
            f"| {r.source:<12} | subsystem: {r.subsystem or 'unknown':<15} "
            f"| tags: {', '.join(r.tags[:3])}"
        )

    # 8. Сохранение
    save(records)

    # 9. Обновление Digital Twin (mock-режим)
    twin = TwinUpdater(mock=True)
    twin.update_batch(records)

    logging.info("=== Pipeline завершён ===")

if __name__ == "__main__":
    run_pipeline()
