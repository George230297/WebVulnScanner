
import asyncio
import functools
import logging
from typing import Callable, Any, Optional

logger = logging.getLogger("WebVulnScanner")


def audit_log(func: Callable) -> Callable:
    """
    Decorator that logs every outgoing request and its response status code to a file.
    Assumes the first positional argument is 'url'.
    """
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Extract URL for logging
        url: str = "Unknown"
        if args:
            url = str(args[0])
        elif 'url' in kwargs:
            url = str(kwargs['url'])

        try:
            result = await func(*args, **kwargs)

            # Determine status code based on return type
            status: Any = "Unknown"
            if hasattr(result, 'status'):
                status = result.status
            elif isinstance(result, tuple) and len(result) >= 2:
                status = result[1]  # (url, status, ...)
            elif isinstance(result, int):
                status = result

            log_entry = f"[AUDIT] Request to {url} - Status: {status}\n"

            try:
                with open("audit.log", "a", encoding="utf-8") as f:
                    f.write(log_entry)
            except IOError as e:
                logger.error(f"Failed to write to audit log: {e}")

            return result

        except Exception as e:
            try:
                with open("audit.log", "a", encoding="utf-8") as f:
                    f.write(f"[AUDIT] Request to {url} - FAILED: {str(e)}\n")
            except IOError:
                pass
            raise

    return wrapper


def retry_network(func: Callable) -> Callable:
    """
    Decorator that retries the function up to 3 times on TimeoutError.
    After exhausting retries, re-raises the last exception.
    """
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        max_retries = 3
        last_exception: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except (asyncio.TimeoutError, TimeoutError) as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(
                        f"Timeout calling {func.__name__}, retrying ({attempt}/{max_retries})..."
                    )
                    await asyncio.sleep(1)
                else:
                    logger.error(
                        f"Timeout calling {func.__name__} after {max_retries} attempts."
                    )

        # BUG-6 FIX: always re-raise if we exhausted retries; never return None silently.
        if last_exception is not None:
            raise last_exception

        # This path is unreachable in practice, but satisfies type checkers.
        return None  # pragma: no cover

    return wrapper
