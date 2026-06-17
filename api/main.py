import logging
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from core.config import settings
from api.v1.routes import router as api_v1_router
from api.cache import init_redis, close_redis
from models.database import init_db

# Configure logging configuration format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown hooks.
    Ensures Redis and Postgres configurations are online.
    """
    logger.info("Initializing application startup sequence...")
    
    # 1. Initialize Postgres database schemas asynchronously
    try:
        # Run sync table generation in a threadpool so it doesn't block the async loop
        await asyncio.to_thread(init_db)
    except Exception as e:
        logger.critical("Critical error during database schema initialization: %s", str(e))
        
    # 2. Establish connections to Redis
    await init_redis()
    
    yield
    
    logger.info("Initializing application shutdown sequence...")
    # 3. Clean up Redis connections
    await close_redis()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise Threat Intelligence Platform (TIP) compliant with STIX 2.1 specifications.",
    lifespan=lifespan
)

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to specific downstream consumers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handling middleware for unexpected application faults
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception occurred on path %s: %s", request.url.path, str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact the security operations team."}
    )

# Root status health check endpoint
@app.get("/health", tags=["System Status"])
async def health_check() -> dict:
    return {
        "status": "healthy",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

# Wire up STIX v1 API routers
app.include_router(api_v1_router, prefix=settings.API_V1_STR, tags=["Threat Indicators"])
