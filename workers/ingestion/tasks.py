import logging
import httpx
from typing import List, Dict, Any, Optional
from workers.celery_app import celery_app
from models.database import get_sync_session
from workers.ingestion.parser import parse_generic_json_feed, upsert_indicators

logger = logging.getLogger(__name__)

@celery_app.task(name="workers.ingestion.ingest_feed_url_task", bind=True, max_retries=3, default_retry_delay=60)
def ingest_feed_url_task(self, feed_url: str, source_name: str) -> Dict[str, Any]:
    """
    Celery task that fetches raw threat feed data from an HTTP endpoint, 
    normalizes the contents, and upserts it into the database.
    """
    logger.info("Starting ingestion task for feed: %s (%s)", source_name, feed_url)
    
    try:
        # Fetch the feed contents with a strict timeout
        with httpx.Client(timeout=15.0) as client:
            response = client.get(feed_url)
            response.raise_for_status()
            feed_data = response.json()
            
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP error fetching feed %s: %s", source_name, exc)
        # Exponential backoff retry for transient network/server issues
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 60)
    except Exception as exc:
        logger.error("Unexpected error fetching feed %s: %s", source_name, exc)
        raise self.retry(exc=exc)
        
    try:
        # Parse the JSON structure
        raw_items = parse_generic_json_feed(feed_data)
        if not raw_items:
            logger.info("No indicators found in feed: %s", source_name)
            return {"status": "success", "count": 0, "source": source_name}
            
        logger.info("Found %d raw items in feed %s. Upserting into DB...", len(raw_items), source_name)
        
        # Write to database using the sync session provider
        with next(get_sync_session()) as session:
            saved_indicators = upsert_indicators(session, raw_items, source_name)
            
            # Dispatch async enrichment tasks for all ingested indicators
            # We import here to prevent circular imports
            from workers.enrichment.manager import enrich_indicator_task
            
            for indicator in saved_indicators:
                # Trigger task asynchronously in the Celery worker pool
                enrich_indicator_task.delay(indicator.id)
                
            session.commit()
            
        logger.info("Ingestion completed successfully for %s. Dispatched %d enrichment tasks.", source_name, len(saved_indicators))
        return {
            "status": "success", 
            "count": len(saved_indicators), 
            "source": source_name
        }
        
    except Exception as exc:
        logger.error("Failed to commit ingestion database transactions for feed %s: %s", source_name, str(exc))
        raise
