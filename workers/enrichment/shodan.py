import logging
import asyncio
import time
import httpx
from typing import Dict, Any, Optional
from core.config import settings

logger = logging.getLogger(__name__)

class ShodanClient:
    """
    Asynchronous client for Shodan API.
    Includes request spacing to respect rate limits (1 request per second for free API keys).
    """
    def __init__(self, api_key: str = None, rate_limit_rps: int = None):
        self.api_key = api_key or settings.SHODAN_API_KEY
        self.rate_limit_rps = rate_limit_rps or settings.SHODAN_RATE_LIMIT_RPS
        self.base_url = "https://api.shodan.io"
        
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def _pace_request(self) -> None:
        """Paces queries to prevent Shodan 429 exceptions."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time
            minimum_interval = 1.0 / self.rate_limit_rps
            
            if elapsed < minimum_interval:
                delay = minimum_interval - elapsed
                logger.debug("Shodan rate limit pacing: sleeping %s seconds...", round(delay, 2))
                await asyncio.sleep(delay)
                
            self.last_request_time = time.monotonic()

    def _get_mock_data(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Provides mock open ports and CVE vulnerability data."""
        # Make mock data dependent on the IP structure or value
        is_vulnerable = len(value) % 2 == 0
        ports = [22, 80, 443]
        if is_vulnerable:
            ports.extend([445, 3389])
            
        vulns = ["CVE-2017-0144"] if is_vulnerable else [] # EternalBlue
        
        return {
            "ports": ports,
            "vulns": vulns,
            "os": "Windows Server" if is_vulnerable else "Ubuntu Linux",
            "x_mocked": True
        }

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Enriches IP addresses and domains using Shodan.
        Returns host data (ports, vulns, hostnames).
        """
        # Shodan is only useful for network assets (IPs / domains)
        if ioc_type not in ("ipv4-addr", "ipv6-addr", "domain-name"):
            return {}

        if self.api_key == "mock_shodan_key" or not self.api_key:
            logger.debug("Shodan API Key is set to mock. Returning mock response for %s", value)
            return self._get_mock_data(ioc_type, value)

        # Enforce rate limiting pacing
        await self._pace_request()

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                if ioc_type in ("ipv4-addr", "ipv6-addr"):
                    # Host lookup
                    url = f"{self.base_url}/shodan/host/{value}?key={self.api_key}"
                    response = await client.get(url)
                    
                    if response.status_code == 404:
                        logger.info("Host %s not found in Shodan database.", value)
                        return {"ports": [], "vulns": []}
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    return {
                        "ports": data.get("ports", []),
                        "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                        "os": data.get("os"),
                        "hostnames": data.get("hostnames", [])
                    }
                else:
                    # DNS resolve lookup for domain-name
                    url = f"{self.base_url}/dns/resolve?domains={value}&key={self.api_key}"
                    response = await client.get(url)
                    response.raise_for_status()
                    data = response.json()
                    
                    resolved_ip = data.get(value)
                    if resolved_ip:
                        # Recurse query for the resolved IP address
                        return await self.enrich_ioc("ipv4-addr", resolved_ip)
                    return {}
                    
            except httpx.HTTPError as exc:
                logger.error("HTTP error calling Shodan API for %s: %s", value, str(exc))
                return {}
            except Exception as exc:
                logger.error("Unexpected error in Shodan enrichment client: %s", str(exc))
                return {}
