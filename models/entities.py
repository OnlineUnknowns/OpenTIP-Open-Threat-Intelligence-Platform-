import datetime
import uuid
from typing import Dict, List, Optional, Any
from sqlmodel import SQLModel, Field, Field as SQLField
from sqlalchemy import Column, JSON, String, Index, DateTime

# Helper to generate STIX 2.1 conformant IDs
def generate_stix_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"

class Indicator(SQLModel, table=True):
    __tablename__ = "indicators"
    
    # STIX 2.1 Common Properties
    id: str = Field(
        default_factory=lambda: generate_stix_id("indicator"),
        primary_key=True,
        description="STIX 2.1 unique identifier (e.g. indicator--<uuid>)"
    )
    type: str = Field(default="indicator", nullable=False)
    spec_version: str = Field(default="2.1", nullable=False)
    created: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    modified: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    
    # Indicator Properties
    pattern: str = Field(
        nullable=False, 
        description="STIX 2.1 detection pattern, e.g. [ipv4-addr:value = '198.51.100.1']"
    )
    pattern_type: str = Field(default="stix", nullable=False)
    
    # Normalized search values (Extracted from pattern for DB query optimization)
    ioc_type: str = Field(
        index=True, 
        nullable=False, 
        description="Normalized type, e.g., 'ipv4-addr', 'ipv6-addr', 'domain-name', 'file-md5', 'file-sha256', 'url'"
    )
    value: str = Field(
        index=True, 
        nullable=False, 
        description="The actual indicator value (e.g., the IP address, domain, or hash string)"
    )
    
    # Threat metadata
    confidence: int = Field(default=50, ge=0, le=100, nullable=False)
    first_seen: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    last_seen: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    
    # Calculated dynamic score
    risk_score: float = Field(default=0.0, index=True, nullable=False)
    
    # JSON arrays and dicts (PostgreSQL JSON compatibility)
    labels: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    object_marking_refs: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    enrichment_data: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}")
    )
    custom_properties: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}")
    )

    # Database performance indexes
    __table_args__ = (
        Index("idx_indicator_ioc_type_value", "ioc_type", "value"),
        Index("idx_indicator_risk_score_last_seen", "risk_score", "last_seen"),
    )


class ThreatActor(SQLModel, table=True):
    __tablename__ = "threat_actors"
    
    # STIX 2.1 Common Properties
    id: str = Field(
        default_factory=lambda: generate_stix_id("threat-actor"),
        primary_key=True,
        description="STIX 2.1 identifier (e.g., threat-actor--<uuid>)"
    )
    type: str = Field(default="threat-actor", nullable=False)
    spec_version: str = Field(default="2.1", nullable=False)
    created: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    modified: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    
    # ThreatActor specific fields
    name: str = Field(index=True, nullable=False, unique=True)
    description: Optional[str] = Field(default=None, nullable=True)
    sophistication: Optional[str] = Field(default=None, description="e.g. innovator, expert, practitioner")
    
    # JSON fields
    aliases: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    roles: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    goals: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    threat_actor_types: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]")
    )
    custom_properties: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}")
    )


class Relationship(SQLModel, table=True):
    __tablename__ = "relationships"
    
    # STIX 2.1 Common Properties
    id: str = Field(
        default_factory=lambda: generate_stix_id("relationship"),
        primary_key=True
    )
    type: str = Field(default="relationship", nullable=False)
    spec_version: str = Field(default="2.1", nullable=False)
    created: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    modified: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    
    # Relationship specific fields
    relationship_type: str = Field(index=True, nullable=False, description="e.g. indicates, uses, attributed-to")
    source_ref: str = Field(index=True, nullable=False, description="STIX reference ID of the source node")
    target_ref: str = Field(index=True, nullable=False, description="STIX reference ID of the target node")
    description: Optional[str] = Field(default=None, nullable=True)
    confidence: int = Field(default=50, ge=0, le=100, nullable=False)
    
    custom_properties: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}")
    )

    # Compound database index for traversing relationship links fast
    __table_args__ = (
        Index("idx_relationship_nodes_type", "source_ref", "target_ref", "relationship_type"),
    )
