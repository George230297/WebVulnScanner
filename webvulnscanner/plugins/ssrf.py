from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability

# Parameters that suggest the endpoint accepts URLs (potential SSRF vectors)
SSRF_CANDIDATES = {'url', 'redirect', 'next', 'uri', 'target', 'dest', 'path', 'return', 'link', 'src'}


class SSRFCheck(BaseCheck):
    """Identifies URL-accepting parameters that may be SSRF candidates."""

    @property
    def name(self) -> str:
        return "SSRF Candidate"

    async def check(
        self,
        session: Any,
        url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not params:
            return vulns

        for k in params:
            k_lower = k.lower()
            # Check for exact match OR substring match (e.g. 'redirect_url' contains 'redirect')
            if k_lower in SSRF_CANDIDATES or any(candidate in k_lower for candidate in SSRF_CANDIDATES):
                vulns.append(Vulnerability(
                    type="SSRF Candidate",
                    url=url,
                    param=k,
                    evidence=f"Parameter '{k}' accepts URLs",
                    severity="Medium"
                ))
        return vulns
