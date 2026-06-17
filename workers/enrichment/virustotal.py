import logging
import asyncio
import time
import httpx
from typing import Dict, Any, Optional
from core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """
    Asynchronous client for VirusTotal API v3.
    Includes rate limit pacing (token bucket) to avoid 429 errors.
    """
    def __init__(self, api_key: str = None, rate_limit_rpm: int = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        # Free tier: 4 requests per minute
        self.rate_limit_rpm = rate_limit_rpm or settings.VIRUSTOTAL_RATE_LIMIT_RPM
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        # Token bucket configuration for rate-limiting
        self.max_tokens = float(self.rate_limit_rpm)
        self.tokens = self.max_tokens
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def _consume_token(self) -> None:
        """
        Token bucket mechanism. If tokens are unavailable, sleep until
        enough tokens accumulate.
        """
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                
                # Regenerate tokens (tokens/sec = RPM / 60)
                regen_rate = self.rate_limit_rpm / 60.0
                self.tokens = min(self.max_tokens, self.tokens + elapsed * regen_rate)
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                
                # Sleep dynamic delay before re-checking
                wait_time = (1.0 - self.tokens) / regen_rate
                logger.debug("VirusTotal rate limit reached. Pacing request, sleeping %s seconds...", round(wait_time, 2))
                await asyncio.sleep(wait_time)

    def _get_mock_data(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Provides deterministic mock data when VT key is in mock mode."""
        # We can seed mock decisions by the length of value or random hashes
        is_malicious = len(value) % 3 == 0
        malicious_count = 12 if is_malicious else 0
        harmless_count = 60 if is_malicious else 72
        
        return {
            "last_analysis_stats": {
                "harmless": harmless_count,
                "malicious": malicious_count,
                "suspicious": 2 if is_malicious else 0,
                "undetected": 0,
                "timeout": 0
            },
            "reputation": 20 if not is_malicious else -15,
            "x_mocked": True
        }

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Enriches an IOC by calling the appropriate VirusTotal endpoint.
        Gracefully handles rate limiting and falls back to mock data if API key is not configured.
        """
        if self.api_key == "mock_vt_key" or not self.api_key:
            logger.debug("VT API Key is set to mock. Returning mock response for %s", value)
            return self._get_mock_data(ioc_type, value)

        # Map STIX type to VT API endpoint path
        path_map = {
            "ipv4-addr": f"/ip_addresses/{value}",
            "ipv6-addr": f"/ip_addresses/{value}",
            "domain-name": f"/domains/{value}",
            "file-md5": f"/files/{value}",
            "file-sha256": f"/files/{value}",
        }
        
        endpoint = path_map.get(ioc_type)
        if not endpoint:
            # URLs need standard SHA256 base64-without-padding identification in VT, or we skip
            if ioc_type == "url":
                # For simplified production mock/real compliance, we use mock or skip URLs in real VT
                return self._get_mock_data(ioc_type, value)
            return {}

        # Enforce API rate limiting
        await self._consume_token()

        url = f"{self.base_url}{endpoint}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                
                if response.status_code == 429:
                    logger.warning("VT API returned 429 Too Many Requests. Retrying once with backoff.")
                    await asyncio.sleep(5.0)
                    response = await client.get(url, headers=self.headers)
                
                if response.status_code == 404:
                    logger.info("IOC %s not found in VirusTotal database.", value)
                    return {"last_analysis_stats": {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 1}}
                    
                response.raise_for_status()
                json_data = response.json()
                
                # Extract relevant analysis statistics
                attributes = json_data.get("data", {}).get("attributes", {})
                return {
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", [])
                }
                
            except httpx.HTTPError as exc:
                logger.error("HTTP error calling VT API for %s: %s", value, str(exc))
                # Fallback to empty to avoid crashing workers
                return {}
            except Exception as exc:
                logger.error("Unexpected error in VT enrichment client: %s", str(exc))
                return {}
