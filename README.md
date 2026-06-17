<div align="center">

<img src="https://capsule-render.vercel.app/api?type=venom&height=220&text=THREAT%20INTEL%20PLATFORM&fontSize=45&color=0:0a0a0a,100:003300&fontColor=00FF41&stroke=00FF41&strokeWidth=1&animation=twinkling" width="100%"/>

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=18&duration=2000&pause=600&color=00FF41&center=true&vCenter=true&multiline=false&repeat=true&width=700&height=45&lines=%5BSYSTEM+BOOT%5D+Threat+Intelligence+Platform+v1.0;%5B*%5D+Ingesting+STIX%2FTAXII+feeds...;%5B*%5D+Normalizing+IOC+data...;%5B*%5D+Enriching+via+VirusTotal+%2F+Shodan...;%5B*%5D+Computing+time-decay+risk+scores...;%5BREADY%5D+API+layer+online.+All+systems+go." alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Celery](https://img.shields.io/badge/Celery-5.3-37814A?style=for-the-badge&logo=celery&logoColor=white)](https://docs.celeryq.dev)
[![Redis](https://img.shields.io/badge/Redis-7.x-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://elastic.co)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![STIX](https://img.shields.io/badge/STIX-2.1-FF6B35?style=for-the-badge&logo=shield&logoColor=white)](https://oasis-open.github.io/cti-documentation/)
[![License](https://img.shields.io/badge/License-MIT-00FF41?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/OnlineUnknowns/Threat-Intelligence-Platform?style=for-the-badge&color=FFD700&logo=github)](https://github.com/OnlineUnknowns/Threat-Intelligence-Platform/stargazers)

</div>

---

<div align="center">
<img src="https://user-images.githubusercontent.com/74038190/212284100-561aa473-3905-4a80-b561-0d28506553ee.gif" width="700">
</div>

---

## 🧠 What Is This?

<img align="right" src="https://user-images.githubusercontent.com/74038190/229223263-cf2e4b07-2615-4f87-9c38-e37600f8381a.gif" width="260"/>

**Threat Intelligence Platform (TIP)** is a production-grade, enterprise-ready cybersecurity platform engineered by a **Principal Software Architect** with 15+ years in the field.

It ingests, normalizes, enriches, and serves threat data at scale — fully aligned with **STIX 2.1 standards**, built on **Clean Architecture / DDD** principles.

> _"Know your enemy before they know you."_

Detect adversaries. Enrich IOCs. Score risk. Respond fast.

<br clear="right"/>

---

## ⚙️ Platform Capabilities

<div align="center">

| Capability | Detail | Status |
|---|---|---|
| 📥 Threat Ingestion | STIX/TAXII, RSS, CVE feeds, OSINT | ✅ Active |
| 🔁 Normalization | STIX 2.1 deduplication & defanging | ✅ Active |
| 🕸️ Relationship Graph | Actors ↔ Malware ↔ IOCs | ✅ Active |
| 🔍 Enrichment Engine | VirusTotal + Shodan + Whois (async) | ✅ Active |
| 📊 Risk Scoring | Time-decay confidence algorithm | ✅ Active |
| 🔒 Secure API | API-Key Auth + RBAC (Analyst/Admin) | ✅ Active |
| ⚡ Redis Caching | IOC lookup cache layer | ✅ Active |
| 🐘 Persistence | PostgreSQL + Elasticsearch | ✅ Active |
| 🐳 Infra-as-Code | Docker Compose + Terraform | ✅ Active |
| 🔄 Async Workers | Celery + Redis task queue | ✅ Active |

</div>

---

## 🗂️ SECTION 1 — Enterprise Directory Structure

> **Clean Architecture + Domain-Driven Design** — each layer only knows about the layer below it. Zero circular dependencies. Zero technical debt accumulation.

```
threat-intelligence-platform/
│
├── 📂 core/                          # ── Domain Layer (pure business logic, zero I/O)
│   ├── 📂 domain/
│   │   ├── entities.py               #    STIX 2.1 domain entities (pure Python dataclasses)
│   │   ├── value_objects.py          #    IOC pattern types, severity enums, confidence range
│   │   └── exceptions.py             #    Domain-level exceptions (DuplicateIOCError, etc.)
│   ├── 📂 scoring/
│   │   ├── risk_engine.py            #    Time-decay risk score algorithm (0–100)
│   │   └── confidence_adjuster.py    #    Bayesian confidence update on re-ingestion
│   ├── 📂 crypto/
│   │   └── hashing.py                #    SHA-256 fingerprinting for dedup keys
│   └── config.py                     #    Pydantic settings (env-driven, no hardcoded secrets)
│
├── 📂 api/                           # ── Interface Layer (HTTP surface area only)
│   ├── 📂 v1/
│   │   ├── routes/
│   │   │   ├── indicators.py         #    GET /indicators, GET /indicators/search
│   │   │   ├── threat_actors.py      #    CRUD for ThreatActor resources
│   │   │   └── relationships.py      #    Graph traversal endpoints
│   │   └── schemas/
│   │       ├── indicator_dto.py      #    Pydantic request/response DTOs
│   │       └── pagination.py         #    Generic paginated response wrapper
│   ├── 📂 middleware/
│   │   ├── auth.py                   #    API-Key extraction + RBAC guard
│   │   ├── rate_limiter.py           #    Sliding window rate limiter (Redis-backed)
│   │   └── cache.py                  #    Redis cache decorator for GET endpoints
│   └── main.py                       #    FastAPI app factory, lifespan, router mounts
│
├── 📂 models/                        # ── Persistence Layer (ORM schemas + migrations)
│   ├── db/
│   │   ├── indicator.py              #    SQLModel: Indicator table + indexes
│   │   ├── threat_actor.py           #    SQLModel: ThreatActor table
│   │   ├── relationship.py           #    SQLModel: STIX Relationship table
│   │   └── api_key.py                #    SQLModel: APIKey + role table
│   └── elastic/
│       └── index_mappings.py         #    Elasticsearch index templates for full-text IOC search
│
├── 📂 workers/                       # ── Application Layer (async orchestration)
│   ├── 📂 ingestion/
│   │   ├── tasks.py                  #    Celery tasks: fetch → parse → deduplicate → store
│   │   ├── parsers/
│   │   │   ├── stix_parser.py        #    STIX 2.1 bundle parser
│   │   │   ├── osint_parser.py       #    Generic JSON/RSS OSINT parser
│   │   │   └── cve_parser.py         #    NVD CVE JSON feed parser
│   │   └── defang.py                 #    URL/IP defanging + re-fanging utilities
│   ├── 📂 enrichment/
│   │   ├── tasks.py                  #    Celery tasks: enqueue enrichment per IOC
│   │   ├── virustotal_client.py      #    Async VT API client with rate-limit backoff
│   │   ├── shodan_client.py          #    Async Shodan client
│   │   └── whois_client.py           #    Async Whois resolution
│   └── celery_app.py                 #    Celery factory: broker + backend config
│
├── 📂 migrations/                    # ── Database migrations (Alembic)
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 0001_initial_schema.py
│
├── 📂 infra/                         # ── Infrastructure as Code
│   ├── 📂 docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.worker
│   │   └── docker-compose.yml        #    Full stack: API + Worker + Redis + PG + ES
│   ├── 📂 terraform/
│   │   ├── main.tf                   #    AWS ECS / GCP Cloud Run deployment
│   │   └── variables.tf
│   └── 📂 nginx/
│       └── nginx.conf                #    Reverse proxy + TLS termination
│
├── 📂 tests/
│   ├── unit/                         #    Domain logic unit tests (no I/O)
│   ├── integration/                  #    DB + Redis + API integration tests
│   └── conftest.py
│
├── .env.example
├── pyproject.toml                    #    Poetry deps + tool config
├── alembic.ini
└── README.md
```

---

## 🗃️ SECTION 2 — Data Models & STIX 2.1 Schemas

```python
# models/db/indicator.py
import uuid
from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, Index, Column
import sqlalchemy as sa

class Indicator(SQLModel, table=True):
    __tablename__ = "indicators"
    __table_args__ = (
        Index("ix_indicators_value_hash", "value_hash"),       # dedup lookup
        Index("ix_indicators_type_score", "ioc_type", "risk_score"),
        Index("ix_indicators_last_seen", "last_seen"),
    )

    id: uuid.UUID               = Field(default_factory=uuid.uuid4, primary_key=True)
    stix_id: str                = Field(index=True, unique=True)   # STIX 2.1 indicator--<uuid>
    pattern: str                = Field()                           # [ipv4-addr:value = '1.2.3.4']
    ioc_type: str               = Field(index=True)                 # ip, domain, hash, url
    value: str                  = Field(index=True)
    value_hash: str             = Field(unique=True)                # SHA-256(type+value) dedup key
    confidence: int             = Field(default=50, ge=0, le=100)  # STIX confidence 0-100
    risk_score: float           = Field(default=0.0)                # computed by scoring engine
    source: str                 = Field(index=True)
    first_seen: datetime        = Field(default_factory=datetime.utcnow)
    last_seen: datetime         = Field(default_factory=datetime.utcnow)
    is_active: bool             = Field(default=True, index=True)
    malicious_verdicts: int     = Field(default=0)
    total_verdicts: int         = Field(default=0)
    raw_data: Optional[dict]    = Field(default=None, sa_column=Column(sa.JSON))
    created_at: datetime        = Field(default_factory=datetime.utcnow)
    updated_at: datetime        = Field(default_factory=datetime.utcnow)


# models/db/threat_actor.py
class ThreatActor(SQLModel, table=True):
    __tablename__ = "threat_actors"

    id: uuid.UUID         = Field(default_factory=uuid.uuid4, primary_key=True)
    stix_id: str          = Field(index=True, unique=True)
    name: str             = Field(index=True)
    aliases: list[str]    = Field(default=[], sa_column=Column(sa.ARRAY(sa.String)))
    description: Optional[str] = Field(default=None)
    sophistication: Optional[str] = Field(default=None)   # minimal, intermediate, advanced
    motivation: Optional[str]     = Field(default=None)
    first_seen: Optional[datetime] = Field(default=None)
    last_seen:  Optional[datetime] = Field(default=None)
    created_at: datetime  = Field(default_factory=datetime.utcnow)


# models/db/relationship.py
class STIXRelationship(SQLModel, table=True):
    __tablename__ = "stix_relationships"
    __table_args__ = (
        Index("ix_rel_source", "source_ref"),
        Index("ix_rel_target", "target_ref"),
        Index("ix_rel_type",   "relationship_type"),
    )

    id: uuid.UUID              = Field(default_factory=uuid.uuid4, primary_key=True)
    stix_id: str               = Field(index=True, unique=True)
    source_ref: str            = Field()   # e.g. threat-actor--<uuid>
    target_ref: str            = Field()   # e.g. indicator--<uuid>
    relationship_type: str     = Field()   # uses, indicates, attributed-to
    description: Optional[str] = Field(default=None)
    created_at: datetime       = Field(default_factory=datetime.utcnow)
```

---

## 🔄 SECTION 3 — Async Ingestion Engine & Robust Parser

```python
# workers/ingestion/defang.py
import re

DEFANG_PATTERNS = [
    (r"http", "hxxp"),
    (r"\.", "[.]"),
    (r"@", "[@]"),
]

def defang(value: str) -> str:
    result = value
    for pattern, replacement in DEFANG_PATTERNS:
        result = re.sub(pattern, replacement, result)
    return result

def refang(value: str) -> str:
    return (value
        .replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("[@]", "@"))


# workers/ingestion/parsers/osint_parser.py
import hashlib, logging
from datetime import datetime
from typing import Iterator
from models.db.indicator import Indicator

logger = logging.getLogger(__name__)

IOC_TYPE_PATTERNS = {
    "ip":     r"^(\d{1,3}\.){3}\d{1,3}$",
    "domain": r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
    "hash":   r"^[a-fA-F0-9]{32,64}$",
    "url":    r"^https?://",
}

def make_value_hash(ioc_type: str, value: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{value.lower()}".encode()).hexdigest()

def detect_ioc_type(value: str) -> str | None:
    import re
    for ioc_type, pattern in IOC_TYPE_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return None

def parse_osint_feed(raw: list[dict], source: str) -> Iterator[Indicator]:
    for entry in raw:
        value = entry.get("value") or entry.get("ioc") or entry.get("indicator")
        if not value:
            continue
        value = value.strip().lower()
        ioc_type = entry.get("type") or detect_ioc_type(value)
        if not ioc_type:
            logger.warning("Cannot detect IOC type for: %s", value)
            continue
        yield Indicator(
            stix_id=f"indicator--{__import__('uuid').uuid4()}",
            pattern=f"[{ioc_type}-addr:value = '{value}']",
            ioc_type=ioc_type,
            value=value,
            value_hash=make_value_hash(ioc_type, value),
            confidence=int(entry.get("confidence", 50)),
            source=source,
            raw_data=entry,
        )


# workers/ingestion/tasks.py
import httpx, logging
from celery_app import celery
from workers.ingestion.parsers.osint_parser import parse_osint_feed
from models.db.indicator import Indicator
from sqlmodel import Session, select
from core.db import engine
from datetime import datetime

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=3, default_retry_delay=60)
def ingest_osint_feed(self, feed_url: str, source: str):
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(feed_url)
            resp.raise_for_status()
            raw = resp.json()

        with Session(engine) as session:
            for indicator in parse_osint_feed(raw, source):
                existing = session.exec(
                    select(Indicator).where(
                        Indicator.value_hash == indicator.value_hash
                    )
                ).first()

                if existing:
                    # Deduplication: update metadata, never duplicate
                    existing.last_seen = datetime.utcnow()
                    existing.confidence = min(100, existing.confidence + 5)
                    existing.total_verdicts += 1
                    session.add(existing)
                    logger.info("Updated existing IOC: %s", existing.value)
                else:
                    session.add(indicator)
                    logger.info("New IOC ingested: %s", indicator.value)

            session.commit()
    except Exception as exc:
        logger.error("Ingestion failed: %s", exc)
        raise self.retry(exc=exc)
```

---

## 📊 SECTION 4 — Enrichment & Time-Decay Scoring Engine

```python
# core/scoring/risk_engine.py
import math
from datetime import datetime, timezone

SOURCE_RELIABILITY = {
    "virustotal": 0.95,
    "shodan":     0.85,
    "alienvault": 0.80,
    "osint":      0.60,
    "unknown":    0.40,
}

def time_decay_factor(last_seen: datetime, half_life_days: float = 30.0) -> float:
    """Exponential decay: score halves every `half_life_days`."""
    delta = (datetime.now(timezone.utc) - last_seen).days
    return math.exp(-math.log(2) * delta / half_life_days)

def compute_risk_score(
    malicious_verdicts: int,
    total_verdicts: int,
    confidence: int,
    source: str,
    last_seen: datetime,
) -> float:
    if total_verdicts == 0:
        return 0.0

    malicious_ratio  = malicious_verdicts / total_verdicts          # 0.0 – 1.0
    reliability      = SOURCE_RELIABILITY.get(source, 0.40)
    confidence_norm  = confidence / 100.0
    decay            = time_decay_factor(last_seen)

    raw_score = (
        malicious_ratio  * 0.50 +
        reliability      * 0.25 +
        confidence_norm  * 0.25
    ) * decay

    return round(min(raw_score * 100, 100.0), 2)


# workers/enrichment/virustotal_client.py
import asyncio, httpx, logging
from core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.headers = {"x-apikey": settings.VT_API_KEY}

    async def lookup_ip(self, ip: str) -> dict:
        async with httpx.AsyncClient(headers=self.headers, timeout=20) as client:
            for attempt in range(3):
                try:
                    r = await client.get(f"{self.BASE}/ip_addresses/{ip}")
                    if r.status_code == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    r.raise_for_status()
                    data = r.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "malicious":  stats.get("malicious", 0),
                        "total":      sum(stats.values()),
                        "reputation": data.get("reputation", 0),
                    }
                except httpx.HTTPError as e:
                    logger.warning("VT attempt %d failed: %s", attempt, e)
        return {}


# workers/enrichment/tasks.py
from celery_app import celery
from workers.enrichment.virustotal_client import VirusTotalClient
from core.scoring.risk_engine import compute_risk_score
from models.db.indicator import Indicator
from sqlmodel import Session, select
from core.db import engine
import asyncio, logging

logger = logging.getLogger(__name__)
vt = VirusTotalClient()

@celery.task(bind=True, max_retries=3, default_retry_delay=120)
def enrich_indicator(self, indicator_id: str):
    with Session(engine) as session:
        ind = session.get(Indicator, indicator_id)
        if not ind:
            return

        try:
            result = asyncio.run(vt.lookup_ip(ind.value)) if ind.ioc_type == "ip" else {}
            if result:
                ind.malicious_verdicts = result.get("malicious", ind.malicious_verdicts)
                ind.total_verdicts     = result.get("total",     ind.total_verdicts)
            ind.risk_score = compute_risk_score(
                malicious_verdicts=ind.malicious_verdicts,
                total_verdicts=ind.total_verdicts,
                confidence=ind.confidence,
                source=ind.source,
                last_seen=ind.last_seen,
            )
            session.add(ind)
            session.commit()
            logger.info("Enriched IOC %s → score=%.1f", ind.value, ind.risk_score)
        except Exception as exc:
            raise self.retry(exc=exc)
```

---

## 🔐 SECTION 5 — Secure API Layer & Query Engine

```python
# api/middleware/auth.py
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from sqlmodel import Session, select
from models.db.api_key import APIKey
from core.db import engine
from enum import Enum

class Role(str, Enum):
    ANALYST = "analyst"
    ADMIN   = "admin"

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_current_role(request: Request, api_key: str = Security(API_KEY_HEADER)) -> Role:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    with Session(engine) as session:
        record = session.exec(
            select(APIKey).where(APIKey.key == api_key, APIKey.is_active == True)
        ).first()
    if not record:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key")
    return Role(record.role)

def require_role(*roles: Role):
    async def checker(role: Role = Security(get_current_role)):
        if role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return role
    return checker


# api/middleware/cache.py
import json, hashlib
from functools import wraps
from fastapi import Request, Response
from redis.asyncio import Redis

def cache_response(ttl: int = 300):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            redis: Redis = request.app.state.redis
            key = "tip:cache:" + hashlib.md5(str(request.url).encode()).hexdigest()
            cached = await redis.get(key)
            if cached:
                return Response(content=cached, media_type="application/json")
            response = await func(request, *args, **kwargs)
            await redis.setex(key, ttl, json.dumps(response))
            return response
        return wrapper
    return decorator


# api/v1/routes/indicators.py
from fastapi import APIRouter, Depends, Query, Request
from sqlmodel import Session, select
from models.db.indicator import Indicator
from api.middleware.auth import require_role, Role
from api.middleware.cache import cache_response
from api.v1.schemas.pagination import Page
from core.db import engine
from typing import Optional
import json

router = APIRouter(prefix="/api/v1/indicators", tags=["Indicators"])

@router.get("/search")
@cache_response(ttl=120)
async def search_indicator(
    request: Request,
    q: str = Query(..., min_length=3, description="IP, domain, hash, or URL"),
    _: Role = Depends(require_role(Role.ANALYST, Role.ADMIN)),
):
    """Search for a single IOC — Redis-cached for 2 minutes."""
    with Session(engine) as session:
        results = session.exec(
            select(Indicator).where(Indicator.value.contains(q)).limit(20)
        ).all()
    return {"query": q, "count": len(results), "results": results}


@router.get("", response_model=Page[Indicator])
async def list_indicators(
    ioc_type:      Optional[str]   = Query(None),
    min_risk:      Optional[float] = Query(None, ge=0, le=100),
    max_risk:      Optional[float] = Query(None, ge=0, le=100),
    is_active:     Optional[bool]  = Query(True),
    page:          int             = Query(1, ge=1),
    page_size:     int             = Query(20, ge=1, le=100),
    _: Role = Depends(require_role(Role.ANALYST, Role.ADMIN)),
):
    """Paginated, filterable indicator listing."""
    with Session(engine) as session:
        query = select(Indicator)
        if ioc_type:  query = query.where(Indicator.ioc_type == ioc_type)
        if min_risk:  query = query.where(Indicator.risk_score >= min_risk)
        if max_risk:  query = query.where(Indicator.risk_score <= max_risk)
        if is_active is not None:
            query = query.where(Indicator.is_active == is_active)
        query = query.order_by(Indicator.risk_score.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        results = session.exec(query).all()
    return Page(items=results, page=page, page_size=page_size)


# api/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from redis.asyncio import Redis
from core.config import settings
from api.v1.routes import indicators, threat_actors, relationships

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    yield
    await app.state.redis.aclose()

app = FastAPI(
    title="Threat Intelligence Platform",
    version="1.0.0",
    description="Enterprise-grade TIP — STIX 2.1 compliant",
    lifespan=lifespan,
)

app.include_router(indicators.router)
app.include_router(threat_actors.router)
app.include_router(relationships.router)
```

---

## 🐳 Infrastructure — Docker Compose

```yaml
# infra/docker/docker-compose.yml
version: "3.9"

services:
  api:
    build:
      context: ../..
      dockerfile: infra/docker/Dockerfile.api
    ports: ["8000:8000"]
    env_file: .env
    depends_on: [postgres, redis, elasticsearch]

  worker:
    build:
      context: ../..
      dockerfile: infra/docker/Dockerfile.worker
    command: celery -A workers.celery_app worker -l info -c 4
    env_file: .env
    depends_on: [postgres, redis]

  beat:
    build:
      context: ../..
      dockerfile: infra/docker/Dockerfile.worker
    command: celery -A workers.celery_app beat -l info
    env_file: .env
    depends_on: [redis]

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: tipdb
      POSTGRES_USER: tip
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes: [pgdata:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 512mb --maxmemory-policy allkeys-lru

  elasticsearch:
    image: elasticsearch:8.12.0
    environment:
      discovery.type: single-node
      ES_JAVA_OPTS: "-Xms512m -Xmx512m"
    volumes: [esdata:/usr/share/elasticsearch/data]

volumes:
  pgdata:
  esdata:
```

---

## 🔧 Tech Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=for-the-badge&logo=celery&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)

</div>

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/OnlineUnknowns/Threat-Intelligence-Platform.git
cd Threat-Intelligence-Platform

# 2. Environment
cp .env.example .env
# Fill in: POSTGRES_PASSWORD, VT_API_KEY, SHODAN_API_KEY, SECRET_KEY

# 3. Launch full stack
docker compose -f infra/docker/docker-compose.yml up -d

# 4. Run migrations
docker exec -it tip_api alembic upgrade head

# 5. Hit the API
curl -H "X-API-Key: your-key" http://localhost:8000/api/v1/indicators/search?q=8.8.8.8
```

---

## 🔐 API Authentication

```bash
# Analyst — read-only access
curl -H "X-API-Key: analyst-key-here" \
     "http://localhost:8000/api/v1/indicators?ioc_type=ip&min_risk=70"

# Admin — full access including management endpoints
curl -H "X-API-Key: admin-key-here" \
     -X POST "http://localhost:8000/api/v1/ingest/trigger"
```

| Role | Permissions |
|---|---|
| `analyst` | Search, list, view indicators & relationships |
| `admin` | All analyst perms + ingest triggers, key management, config |

---

## 📐 Risk Score Formula

```
RiskScore = (
    malicious_ratio  × 0.50 +
    src_reliability  × 0.25 +
    confidence_norm  × 0.25
) × e^( -ln(2) × age_days / 30 )  × 100

Where:
  • malicious_ratio  = malicious_verdicts / total_verdicts
  • src_reliability  = per-source constant (VT=0.95, OSINT=0.60)
  • confidence_norm  = STIX confidence / 100
  • half-life        = 30 days (score halves every month of inactivity)
```

---

## 🤝 Contributing

```bash
git checkout -b feat/your-feature
git commit -m "feat: describe your change"
git push origin feat/your-feature
# Open a Pull Request
```

---

## ⚠️ Disclaimer

> This platform is intended for **authorized security research, defensive operations, and educational purposes only**. Do not use against infrastructure you do not own or have explicit written permission to test.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0a0a0a,100:003300&height=120&section=footer&text=Stay+Secure.+Stay+Silent.&fontColor=00FF41&fontSize=22&fontAlignY=70&animation=twinkling" width="100%"/>

**Built with 🛡️ by [OnlineUnknowns](https://github.com/OnlineUnknowns)**

<img src="https://komarev.com/ghpvc/?username=OnlineUnknowns&label=Profile+Views&color=00FF41&style=flat" alt="Views"/>

</div>
