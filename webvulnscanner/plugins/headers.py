from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import SECURITY_HEADERS

class SecurityHeadersCheck(BaseCheck):
    name = "Security Headers"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not headers:
            return vulns
            
        # Case insensitive header check
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
