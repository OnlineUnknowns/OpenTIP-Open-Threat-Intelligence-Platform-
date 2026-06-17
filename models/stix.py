import datetime
import uuid
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field

class STIXBaseDTO(BaseModel):
    id: str
    type: str
    spec_version: str = "2.1"
    created: datetime.datetime
    modified: datetime.datetime
    confidence: Optional[int] = 50
    labels: Optional[List[str]] = Field(default_factory=list)
    object_marking_refs: Optional[List[str]] = Field(default_factory=list)
    custom_properties: Optional[Dict[str, Any]] = Field(default_factory=dict)

class STIXIndicatorDTO(STIXBaseDTO):
    type: str = "indicator"
    pattern: str
    pattern_type: str = "stix"
    pattern_version: Optional[str] = "2.1"
    valid_from: datetime.datetime
    valid_until: Optional[datetime.datetime] = None

class STIXThreatActorDTO(STIXBaseDTO):
    type: str = "threat-actor"
    name: str
    description: Optional[str] = None
    threat_actor_types: Optional[List[str]] = Field(default_factory=list)
    aliases: Optional[List[str]] = Field(default_factory=list)
    roles: Optional[List[str]] = Field(default_factory=list)
    goals: Optional[List[str]] = Field(default_factory=list)
    sophistication: Optional[str] = None

class STIXRelationshipDTO(STIXBaseDTO):
    type: str = "relationship"
    relationship_type: str
    source_ref: str
    target_ref: str
    description: Optional[str] = None

class STIXBundleDTO(BaseModel):
    type: str = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid.uuid4()}")
    objects: List[Union[STIXIndicatorDTO, STIXThreatActorDTO, STIXRelationshipDTO, Dict[str, Any]]] = Field(default_factory=list)


# Conversion helper functions to convert DB SQLModels to STIX-compliant dicts
def indicator_db_to_stix(indicator: Any) -> Dict[str, Any]:
    """Serializes a DB Indicator SQLModel to a STIX 2.1 JSON representation."""
    stix_obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator.id,
        "created": indicator.created.isoformat(),
        "modified": indicator.modified.isoformat(),
        "pattern": indicator.pattern,
        "pattern_type": indicator.pattern_type,
        "pattern_version": "2.1",
        "valid_from": indicator.first_seen.isoformat(),
        "confidence": indicator.confidence,
        "labels": indicator.labels,
        "object_marking_refs": indicator.object_marking_refs,
        # We place our calculated risk score in custom properties as allowed by STIX 2.1 specs
        "x_opencti_detection": True,  # Common extension field
        "x_tip_risk_score": indicator.risk_score,
        "x_tip_ioc_type": indicator.ioc_type,
        "x_tip_value": indicator.value,
        "x_tip_enrichment": indicator.enrichment_data
    }
    
    # Merge custom properties
    if indicator.custom_properties:
        stix_obj.update(indicator.custom_properties)
        
    return stix_obj

def threat_actor_db_to_stix(ta: Any) -> Dict[str, Any]:
    """Serializes a DB ThreatActor SQLModel to a STIX 2.1 JSON representation."""
    stix_obj = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": ta.id,
        "created": ta.created.isoformat(),
        "modified": ta.modified.isoformat(),
        "name": ta.name,
        "description": ta.description,
        "aliases": ta.aliases,
        "roles": ta.roles,
        "goals": ta.goals,
        "threat_actor_types": ta.threat_actor_types,
        "sophistication": ta.sophistication
    }
    
    if ta.custom_properties:
        stix_obj.update(ta.custom_properties)
        
    return stix_obj

def relationship_db_to_stix(rel: Any) -> Dict[str, Any]:
    """Serializes a DB Relationship SQLModel to a STIX 2.1 JSON representation."""
    stix_obj = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel.id,
        "created": rel.created.isoformat(),
        "modified": rel.modified.isoformat(),
        "relationship_type": rel.relationship_type,
        "source_ref": rel.source_ref,
        "target_ref": rel.target_ref,
        "description": rel.description,
        "confidence": rel.confidence
    }
    
    if rel.custom_properties:
        stix_obj.update(rel.custom_properties)
        
    return stix_obj
