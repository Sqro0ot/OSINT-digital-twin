import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from main import run_pipeline
from config import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

scheduler = BlockingScheduler()

scheduler.add_job(
    run_pipeline,
    "interval",
    seconds=config.INTERVAL_SHODAN,
    id="osint_pipeline",
    max_instances=1
)

if __name__ == "__main__":
    logging.info("Scheduler запущен. Первый запуск немедленно...")
    run_pipeline()   # сразу при старте
    scheduler.start()
