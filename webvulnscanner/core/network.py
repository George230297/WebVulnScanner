
import aiohttp
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from webvulnscanner.utils.decorators import audit_log, retry_network

@dataclass
class ProbeResponse:
    status: int
    text: str
    headers: Optional[Dict[str, str]] = field(default_factory=dict)

@audit_log
@retry_network
async def send_probe(url: str, payload: Optional[Dict[str, Any]] = None, method: str = "POST", params: Optional[Dict[str, Any]] = None) -> ProbeResponse:
    """
    Sends a probe request to the target URL.
    Retries on timeout and logs results.
    
    Args:
        url: The target URL.
        payload: Dictionary containing the JSON payload (for POST/PUT).
        method: HTTP method (POST, GET, etc.).
        params: URL parameters (primarily for GET).
        
    Returns:
        ProbeResponse object containing status and text.
    """
    # Use a short timeout for the probe (5s connect, 10s total)
    timeout = aiohttp.ClientTimeout(total=10, connect=5)
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.request(method, url, json=payload, params=params) as response:
            try:
                # Read content explicitly
                text = await response.text()
            except UnicodeDecodeError:
                text = await response.text(errors='replace')
            
            return ProbeResponse(
                status=response.status,
                text=text,
                headers=dict(response.headers)
            )
