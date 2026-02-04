
import asyncio
import functools
import logging
from typing import Callable, Any

logger = logging.getLogger("WebVulnScanner")

def audit_log(func: Callable) -> Callable:
    """
    Decorator that logs every outgoing request and its response status code to a file.
    Assumes the first argument is 'url'.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract URL for logging
        url = "Unknown"
        if args:
            url = args[0]
        elif 'url' in kwargs:
            url = kwargs['url']

        try:
            result = await func(*args, **kwargs)
            
            # Determine status code based on return type
            status = "Unknown"
            if hasattr(result, 'status'):
                 status = result.status
            elif isinstance(result, tuple) and len(result) >= 2:
                 status = result[1] # Assuming (url, status, ...)
            elif isinstance(result, int):
                status = result
                
            log_entry = f"[AUDIT] Request to {url} - Status: {status}\n"
            
            # Append to audit file
            try:
                with open("audit.log", "a", encoding="utf-8") as f:
                    f.write(log_entry)
            except IOError as e:
                logger.error(f"Failed to write to audit log: {e}")

            return result
            
        except Exception as e:
            # Log failure
            try:
                with open("audit.log", "a", encoding="utf-8") as f:
                    f.write(f"[AUDIT] Request to {url} - FAILED: {str(e)}\n")
            except IOError:
                pass
            raise e

    return wrapper

def retry_network(func: Callable) -> Callable:
    """
    Decorator that retries the function 3 times automatically if a Timeout occurs.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        max_retries = 3
        last_exception = None
        
        for attempt in range(1, max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except (asyncio.TimeoutError, TimeoutError) as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(f"Timeout calling {func.__name__}, retrying ({attempt}/{max_retries})...")
                    await asyncio.sleep(1) # Short backoff
                else:
                    logger.error(f"Timeout calling {func.__name__} after {max_retries} attempts.")
        
        if last_exception:
            raise last_exception
            
    return wrapper
