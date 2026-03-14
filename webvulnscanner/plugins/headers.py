from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import SECURITY_HEADERS


class SecurityHeadersCheck(BaseCheck):
    """Checks for missing HTTP security headers in the response."""

    @property
    def name(self) -> str:
        return "Security Headers"

    async def check(
        self,
        session: Any,
        url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not headers:
            return vulns

        # Case-insensitive header comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, msg in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                vulns.append(Vulnerability(
                    type="Missing Security Header",
                    url=url,
                    evidence=header,
                    severity="Low"
                ))
        return vulns
