from abc import ABC, abstractmethod
from typing import List, Dict, Any
from webvulnscanner.models.vulnerability import Vulnerability

class BaseCheck(ABC):
    """Abstract Base Class for all vulnerability checks."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    async def check(self, session, url: str, html: str = "", headers: dict = None, params: dict = None) -> List[Vulnerability]:
        """
        Main check method.
        :param session: aiohttp session for making active requests
        :param url: Current URL being scanned
        :param html: HTML content of the page (for passive checks)
        :param headers: Response headers (for passive checks)
        :param params: URL parameters (for checking XSS/SQLi injection points)
        :return: List of found vulnerabilities
        """
        return []
