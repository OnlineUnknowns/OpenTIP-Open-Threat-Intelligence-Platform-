import os
from celery import Celery
from core.config import settings

# Create Celery instance
celery_app = Celery(
    "threat_intel_workers",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "workers.ingestion.tasks",
        "workers.enrichment.manager"
    ]
)

# Recommended settings for production workers
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Concurrency and rate limiting tuning
    worker_prefetch_multiplier=1, # Crucial for rate-limited external API scraping tasks
    task_acks_late=True,          # Ensure tasks are retried if worker process fails
    task_reject_on_worker_lost=True
)

if __name__ == "__main__":
    celery_app.start()
