import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlmodel import Session
from models.database import get_async_session
from models.entities import Indicator, ThreatActor, Relationship
from models.stix import indicator_db_to_stix, relationship_db_to_stix, threat_actor_db_to_stix
from api.auth import require_analyst, require_admin
from api.cache import cache_response
from workers.ingestion.tasks import ingest_feed_url_task

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/indicators/search", dependencies=[Depends(require_analyst)])
@cache_response(ttl=60)  # Cache search requests for 60 seconds
async def search_indicator(
    request: Request,
    q: str = Query(..., description="The indicator value to search (e.g. IP, Hash, Domain)"),
    db: AsyncSession = Depends(get_async_session)
) -> List[Dict[str, Any]]:
    """
    Search endpoint targeting exact match on the indicator value.
    Leverages compound index lookups and is accelerated via Redis caching.
    """
    logger.info("Search triggered for query: %s", q)
    query_val = q.strip()
    
    # Run exact lookup against indexed value
    stmt = select(Indicator).where(Indicator.value == query_val)
    result = await db.execute(stmt)
    indicators = result.scalars().all()
    
    # Return as list of STIX 2.1 compliant indicator dicts
    return [indicator_db_to_stix(ind) for ind in indicators]


@router.get("/indicators", dependencies=[Depends(require_analyst)])
async def list_indicators(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type, e.g. ipv4-addr, file-sha256"),
    min_risk: Optional[float] = Query(None, ge=0, le=100, description="Minimum risk score threshold"),
    max_risk: Optional[float] = Query(None, ge=0, le=100, description="Maximum risk score threshold"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100, description="Minimum reporter confidence"),
    limit: int = Query(20, ge=1, le=100, description="Pagination limit"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_async_session)
) -> Dict[str, Any]:
    """
    Retrieves a paginated list of threat indicators.
    Allows filtering by type, severity confidence, and dynamic risk score range.
    """
    conditions = []
    
    if ioc_type:
        conditions.append(Indicator.ioc_type == ioc_type.lower())
    if min_risk is not None:
        conditions.append(Indicator.risk_score >= min_risk)
    if max_risk is not None:
        conditions.append(Indicator.risk_score <= max_risk)
    if min_confidence is not None:
        conditions.append(Indicator.confidence >= min_confidence)
        
    stmt = select(Indicator)
    if conditions:
        stmt = stmt.where(and_(*conditions))
        
    # Order by risk score descending (highest risk first) and last_seen
    stmt = stmt.order_by(Indicator.risk_score.desc(), Indicator.last_seen.desc()).limit(limit).offset(offset)
    
    result = await db.execute(stmt)
    indicators = result.scalars().all()
    
    return {
        "count": len(indicators),
        "limit": limit,
        "offset": offset,
        "results": [indicator_db_to_stix(ind) for ind in indicators]
    }


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
async def trigger_ingestion(
    feed_url: str = Query(..., description="HTTP URL of the JSON threat intelligence feed"),
    source_name: str = Query(..., description="Identifying name of the feed provider")
) -> Dict[str, str]:
    """
    Administrative endpoint to kick off an asynchronous feed ingestion task in background Celery workers.
    Returns the task identifier immediately.
    """
    # Trigger Celery background task
    task = ingest_feed_url_task.delay(feed_url, source_name)
    
    return {
        "message": "Ingestion task triggered successfully.",
        "task_id": task.id,
        "status": "PENDING"
    }


@router.get("/indicators/{indicator_id}/relationships", dependencies=[Depends(require_analyst)])
async def get_indicator_relationships(
    indicator_id: str,
    db: AsyncSession = Depends(get_async_session)
) -> List[Dict[str, Any]]:
    """
    Retrieves all relationships and associated node entities mapped to a given Indicator.
    Traverses the relationships graph edge connections (e.g. indicates, uses).
    """
    # Verify indicator existence
    ind_stmt = select(Indicator).where(Indicator.id == indicator_id)
    ind_result = await db.execute(ind_stmt)
    indicator = ind_result.scalar_one_or_none()
    
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator with ID {indicator_id} not found."
        )
        
    # Select relationships where source or target is the indicator id
    rel_stmt = select(Relationship).where(
        (Relationship.source_ref == indicator_id) | (Relationship.target_ref == indicator_id)
    )
    rel_result = await db.execute(rel_stmt)
    relationships = rel_result.scalars().all()
    
    return [relationship_db_to_stix(rel) for rel in relationships]
