
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
    
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Construct the full URL manually if params are provided.
            if params:
                from urllib.parse import urlencode, urlunparse, urlparse
                parsed_url = urlparse(url)
                query_string = urlencode(params, doseq=True)
                url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query_string, parsed_url.fragment))
                
            async with session.request(method, url, json=payload) as response:
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
    except asyncio.TimeoutError:
        return ProbeResponse(status=0, text="Request Timeout", headers={})
    except aiohttp.ClientError as e:
        return ProbeResponse(status=0, text=f"Client Error: {str(e)}", headers={})
    except Exception as e:
        return ProbeResponse(status=0, text=f"Unexpected Error: {str(e)}", headers={})
