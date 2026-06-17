import functools
import logging
import json
from typing import Optional
from fastapi import Request, Response
from redis.asyncio import Redis, from_url
from core.config import settings

logger = logging.getLogger(__name__)

# Single Redis Client holder
redis_client: Optional[Redis] = None

async def init_redis() -> None:
    """Initializes the global asynchronous Redis client connection."""
    global redis_client
    try:
        redis_client = from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
        # Test connection
        await redis_client.ping()
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.error("Failed to connect to Redis: %s. Caching will be disabled.", str(e))
        redis_client = None

async def close_redis() -> None:
    """Closes the Redis client connection pool."""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Closed Redis connection.")


def cache_response(ttl: int = None):
    """
    FastAPI caching decorator. Caches JSON responses using Redis.
    Falls back gracefully if Redis is unavailable.
    """
    if ttl is None:
        ttl = settings.DEFAULT_CACHE_TTL_SECONDS

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Locate Request object in parameters to build cache key
            request: Optional[Request] = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                for val in kwargs.values():
                    if isinstance(val, Request):
                        request = val
                        break
                        
            # If no request object was found, execute the route without caching
            if not request or not redis_client:
                return await func(*args, **kwargs)
                
            # Construct a unique cache key based on the URL path and sorted query params
            query_str = sorted(list(request.query_params.items()))
            cache_key = f"cache:{request.url.path}:{json.dumps(query_str)}"
            
            try:
                # Attempt cache hit
                cached_data = await redis_client.get(cache_key)
                if cached_data:
                    logger.debug("Cache hit for key: %s", cache_key)
                    # Parse and return JSON response
                    return json.loads(cached_data)
            except Exception as e:
                logger.error("Redis cache read error: %s", str(e))
                
            # Cache miss - execute route
            result = await func(*args, **kwargs)
            
            try:
                # Store serialized result in cache
                # Handles dicts or models (if they are dictionaries/serializable objects)
                # To handle FastAPI responses, we serialize the returned data
                serialized = json.dumps(result, default=str)
                await redis_client.setex(cache_key, ttl, serialized)
                logger.debug("Cache store for key: %s (TTL: %d)", cache_key, ttl)
            except Exception as e:
                logger.error("Redis cache write error: %s", str(e))
                
            return result
        return wrapper
    return decorator
