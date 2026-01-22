import re
from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import REGEX_SECRETS

class SecretsCheck(BaseCheck):
    name = "Secrets & Tokens"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not html:
            return vulns
            
        for name, regex in REGEX_SECRETS.items():
            matches = re.findall(regex, html)
            for m in matches:
                evidence = m[0] if isinstance(m, tuple) else m
                # Simple truncation only for report
                display_evidence = f"{evidence[:20]}..." if len(evidence) > 20 else evidence
                
                vulns.append(Vulnerability(
                    type="JS Secret Leak",
                    url=url,
                    evidence=f"{name}: {display_evidence}",
                    severity="High"
                ))
        return vulns
