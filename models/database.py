import logging
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, create_engine, Session
from core.config import settings

logger = logging.getLogger(__name__)

# -------------------------------------------------------------
# 1. ASYNC DATABASE CONFIGURATION (FastAPI / API endpoints)
# -------------------------------------------------------------
async_engine = create_async_engine(
    settings.DATABASE_URL_ASYNC,
    echo=False,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True
)

async_session_factory = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection helper for obtaining async db sessions in routes."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("Database transaction rolled back due to error: %s", str(e))
            raise
        finally:
            await session.close()


# -------------------------------------------------------------
# 2. SYNC DATABASE CONFIGURATION (Celery Tasks / Sync pipelines)
# -------------------------------------------------------------
sync_engine = create_engine(
    settings.DATABASE_URL_SYNC,
    echo=False,
    pool_size=10,
    max_overflow=5,
    pool_pre_ping=True
)

sync_session_factory = sessionmaker(
    bind=sync_engine,
    class_=Session,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

def get_sync_session() -> Generator[Session, None, None]:
    """Helper context for worker threads to run transactional database logic."""
    with sync_session_factory() as session:
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("Sync database transaction rolled back due to error: %s", str(e))
            raise
        finally:
            session.close()


# -------------------------------------------------------------
# 3. SCHEMA INITIALIZATION
# -------------------------------------------------------------
def init_db() -> None:
    """Sync table creation logic. Run during container setup / bootstrap."""
    logger.info("Initializing database tables...")
    try:
        SQLModel.metadata.create_all(sync_engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error("Failed to initialize database tables: %s", str(e))
        raise
