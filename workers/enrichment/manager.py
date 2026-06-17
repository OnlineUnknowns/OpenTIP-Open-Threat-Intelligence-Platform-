import asyncio
import logging
from typing import Dict, Any
from workers.celery_app import celery_app
from models.database import get_sync_session
from models.entities import Indicator
from workers.enrichment.virustotal import VirusTotalClient
from workers.enrichment.shodan import ShodanClient
from core.domain.scoring import compute_final_risk_score

logger = logging.getLogger(__name__)

def run_async(coro):
    """Safely runs an async coroutine inside a synchronous Celery worker execution thread."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

async def execute_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    """Coordinates enrichment API queries concurrently."""
    vt_client = VirusTotalClient()
    shodan_client = ShodanClient()
    
    # Trigger tasks concurrently
    vt_task = vt_client.enrich_ioc(ioc_type, value)
    shodan_task = shodan_client.enrich_ioc(ioc_type, value)
    
    # Wait for both tasks to complete concurrently
    vt_result, shodan_result = await asyncio.gather(vt_task, shodan_task, return_exceptions=True)
    
    enrichment_data = {}
    
    if isinstance(vt_result, dict):
        enrichment_data["virustotal"] = vt_result
    else:
        logger.error("VirusTotal enrichment returned exception: %s", str(vt_result))
        enrichment_data["virustotal"] = {}
        
    if isinstance(shodan_result, dict):
        enrichment_data["shodan"] = shodan_result
    else:
        logger.error("Shodan enrichment returned exception: %s", str(shodan_result))
        enrichment_data["shodan"] = {}
        
    return enrichment_data


@celery_app.task(name="workers.enrichment.enrich_indicator_task", bind=True, max_retries=3, default_retry_delay=30)
def enrich_indicator_task(self, indicator_id: str) -> Dict[str, Any]:
    """
    Celery task that fetches an indicator, runs VirusTotal + Shodan enrichments,
    merges details, and updates the dynamic risk score.
    """
    logger.info("Enriching indicator ID: %s", indicator_id)
    
    # 1. Retrieve the indicator from database
    with next(get_sync_session()) as session:
        indicator = session.get(Indicator, indicator_id)
        if not indicator:
            logger.warning("Indicator with ID %s not found. Skipping enrichment.", indicator_id)
            return {"status": "skipped", "reason": "not_found"}
            
        ioc_type = indicator.ioc_type
        value = indicator.value
        
        # 2. Call APIs concurrently using async runner
        try:
            enrichment_results = run_async(execute_enrichment(ioc_type, value))
        except Exception as exc:
            logger.error("Enrichment API lookup failed for indicator %s: %s", value, str(exc))
            # Retry background task if transient network error occurred
            raise self.retry(exc=exc)
            
        # 3. Merge new enrichment data with existing enrichment data
        existing_enrichment = indicator.enrichment_data or {}
        # Reassign a new dictionary to trigger SQLAlchemy/SQLModel dirty detection
        indicator.enrichment_data = {**existing_enrichment, **enrichment_results}
        
        # 4. Compute the final risk score combining source and enrichment values
        new_risk_score = compute_final_risk_score(
            ioc_type=indicator.ioc_type,
            confidence=indicator.confidence,
            last_seen=indicator.last_seen,
            enrichment_data=indicator.enrichment_data
        )
        
        indicator.risk_score = new_risk_score
        session.add(indicator)
        session.commit()
        
        logger.info(
            "Enrichment completed for indicator %s. Risk score recalculated: %s", 
            value, 
            new_risk_score
        )
        
    return {
        "status": "success", 
        "indicator_id": indicator_id, 
        "risk_score": new_risk_score
    }
