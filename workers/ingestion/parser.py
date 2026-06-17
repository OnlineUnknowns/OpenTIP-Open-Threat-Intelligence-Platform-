import re
import datetime
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.dialects.postgresql import insert
from sqlmodel import Session, select
from models.entities import Indicator, generate_stix_id
from core.domain.scoring import compute_final_risk_score

logger = logging.getLogger(__name__)

# Regular expressions for identifying IOC types from values
IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
IPV6_REGEX = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")
MD5_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")
SHA256_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


def identify_ioc_type(value: str) -> str:
    """
    Identifies the STIX-compliant cyber observable type based on string patterns.
    Returns: 'ipv4-addr', 'ipv6-addr', 'domain-name', 'file-md5', 'file-sha256', 'url', or 'unknown'
    """
    val = value.strip()
    if IPV4_REGEX.match(val):
        return "ipv4-addr"
    if IPV6_REGEX.match(val):
        return "ipv6-addr"
    if SHA256_REGEX.match(val):
        return "file-sha256"
    if MD5_REGEX.match(val):
        return "file-md5"
    if URL_REGEX.match(val):
        return "url"
    if DOMAIN_REGEX.match(val):
        return "domain-name"
    return "unknown"


def defang_value(ioc_type: str, value: str) -> str:
    """
    Defangs dangerous observable values to prevent accidental activation.
    e.g., http://malicious.com -> hxxp://malicious[.]com
    """
    val = value.strip()
    if ioc_type in ("ipv4-addr", "ipv6-addr"):
        # Replace the last octet separator with [.] or last colon with [:]
        if ioc_type == "ipv4-addr":
            parts = val.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
        return val.replace(":", "[:]")
        
    elif ioc_type == "domain-name":
        # e.g., badsite.com -> badsite[.]com
        parts = val.split(".")
        if len(parts) >= 2:
            return f"{'.'.join(parts[:-1])}[.]{parts[-1]}"
        return val
        
    elif ioc_type == "url":
        # Replace http -> hxxp, https -> hxxps, and defang the domain part
        val = val.replace("http://", "hxxp://").replace("https://", "hxxps://")
        # Find first slash after schema
        schema_len = 8 if val.startswith("hxxps://") else 7
        slash_idx = val.find("/", schema_len)
        domain_part = val[schema_len:slash_idx] if slash_idx != -1 else val[schema_len:]
        
        # Defang domain within url
        defanged_domain = defang_value("domain-name", domain_part)
        
        if slash_idx != -1:
            return val[:schema_len] + defanged_domain + val[slash_idx:]
        return val[:schema_len] + defanged_domain
        
    return val  # Hashes don't need defanging


def parse_stix_pattern(ioc_type: str, value: str) -> str:
    """Generates standard STIX 2.1 pattern string from type and value."""
    if ioc_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "ipv6-addr":
        return f"[ipv6-addr:value = '{value}']"
    elif ioc_type == "domain-name":
        return f"[domain-name:value = '{value}']"
    elif ioc_type == "file-md5":
        return f"[file:hashes.md5 = '{value}']"
    elif ioc_type == "file-sha256":
        return f"[file:hashes.sha256 = '{value}']"
    elif ioc_type == "url":
        return f"[url:value = '{value}']"
    return f"[x-custom-observable:value = '{value}']"


def upsert_indicators(
    session: Session, 
    raw_indicators: List[Dict[str, Any]], 
    source_name: str
) -> List[Indicator]:
    """
    Performs batch PostgreSQL UPSERT (ON CONFLICT DO UPDATE) for high-performance deduplication.
    If an indicator value + ioc_type exists:
      1. Updates last_seen to now.
      2. Increases confidence marginally (up to 100).
      3. Recalculates the dynamic risk score.
      4. Avoids row duplication.
    """
    saved_indicators = []
    now = datetime.datetime.now(datetime.timezone.utc)
    
    for raw in raw_indicators:
        val = raw["value"].strip()
        ioc_type = identify_ioc_type(val)
        
        if ioc_type == "unknown":
            logger.warning("Skipping unknown IOC format: %s", val)
            continue
            
        pattern = parse_stix_pattern(ioc_type, val)
        confidence = raw.get("confidence", 50)
        
        # Check if the indicator already exists
        statement = select(Indicator).where(
            Indicator.ioc_type == ioc_type,
            Indicator.value == val
        )
        existing = session.exec(statement).first()
        
        if existing:
            # DEDUPLICATION LOGIC:
            # Update last seen
            existing.last_seen = now
            existing.modified = now
            
            # Boost confidence slightly based on multiple sightings (+5 per sighting, max 100)
            existing.confidence = min(existing.confidence + 5, 100)
            
            # Record source info in custom properties
            sources = list(existing.custom_properties.get("reporting_sources", []))
            if source_name not in sources:
                sources.append(source_name)
            # Reassign a new dictionary to trigger SQLAlchemy/SQLModel dirty detection
            existing.custom_properties = {
                **existing.custom_properties,
                "reporting_sources": sources
            }
                
            # Recalculate dynamic risk score with new time and confidence
            existing.risk_score = compute_final_risk_score(
                ioc_type=existing.ioc_type,
                confidence=existing.confidence,
                last_seen=existing.last_seen,
                enrichment_data=existing.enrichment_data
            )
            
            session.add(existing)
            saved_indicators.append(existing)
            logger.debug("Deduplicated indicator: %s (New risk score: %s)", val, existing.risk_score)
        else:
            # NEW INDICATOR LOGIC:
            defanged = defang_value(ioc_type, val)
            new_id = generate_stix_id("indicator")
            
            # Compute initial risk score
            initial_score = compute_final_risk_score(
                ioc_type=ioc_type,
                confidence=confidence,
                last_seen=now,
                enrichment_data={}
            )
            
            new_indicator = Indicator(
                id=new_id,
                type="indicator",
                spec_version="2.1",
                created=now,
                modified=now,
                pattern=pattern,
                pattern_type="stix",
                ioc_type=ioc_type,
                value=val,
                confidence=confidence,
                first_seen=now,
                last_seen=now,
                risk_score=initial_score,
                labels=raw.get("labels", []),
                custom_properties={
                    "reporting_sources": [source_name],
                    "defanged_value": defanged
                }
            )
            session.add(new_indicator)
            saved_indicators.append(new_indicator)
            logger.debug("Ingested new indicator: %s (Initial risk score: %s)", val, initial_score)
            
    # Commit transaction to persist
    session.commit()
    return saved_indicators


def parse_generic_json_feed(feed_content: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Parses a generic array-of-objects JSON feed.
    Expects objects with at least:
      - 'indicator' / 'value' / 'ioc' string
      - Optional 'confidence' int
      - Optional 'labels' list
    """
    parsed_items = []
    for item in feed_content:
        # Gracefully handle varying common key naming schemas
        value = item.get("indicator") or item.get("value") or item.get("ioc")
        if not value or not isinstance(value, str):
            continue
            
        confidence = item.get("confidence") or item.get("confidence_score") or 50
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            confidence = 50
            
        labels = item.get("labels") or item.get("tags") or []
        if isinstance(labels, str):
            labels = [labels]
            
        parsed_items.append({
            "value": value,
            "confidence": confidence,
            "labels": list(labels)
        })
    return parsed_items
