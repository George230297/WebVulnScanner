from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from webvulnscanner.models.vulnerability import Vulnerability


class BaseCheck(ABC):
    """Abstract Base Class for all vulnerability checks.
    
    Subclasses MUST implement:
      - name (as a @property returning a str)
      - check (async method returning List[Vulnerability])
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable name for this check."""
        ...

    async def check(
        self,
        session: Any,
        url: str,
        html: str = "",
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        """Main check method.

        Args:
            session: aiohttp.ClientSession for making active requests.
            url: Current URL being scanned.
            html: HTML content of the page (for passive checks).
            headers: Response headers (for passive checks).
            params: URL parameters (for injection checks like XSS/SQLi).

        Returns:
            List of found Vulnerability objects.
        """
        return []

class BaseNetworkPlugin(ABC):
    """Abstract Base Class for all network vulnerability checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable name for this check."""
        ...

    @abstractmethod
    async def check_service(self, ip: str, port: int) -> List[Vulnerability]:
        """Main check method for network services.

        Args:
            ip: Target IP address.
            port: Open port detected.

        Returns:
            List of found Vulnerability objects.
        """
        return []
