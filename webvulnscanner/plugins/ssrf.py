from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability

class SSRFCheck(BaseCheck):
    name = "SSRF Candidate"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not params: return vulns
        
        candidates = ['url', 'redirect', 'next', 'uri', 'target', 'dest']
        
        for k in params:
            if k.lower() in candidates:
                vulns.append(Vulnerability(
                    type="SSRF Candidate",
                    url=url,
                    param=k,
                    evidence="Param accepts URLs",
                    severity="Medium"
                ))
        return vulns
