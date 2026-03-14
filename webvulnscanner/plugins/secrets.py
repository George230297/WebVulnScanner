import re
from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import REGEX_SECRETS


class SecretsCheck(BaseCheck):
    """Checks for hardcoded secrets, API keys and tokens in HTML/JS content."""

    @property
    def name(self) -> str:
        return "Secrets & Tokens"

    async def check(
        self,
        session: Any,
        url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not html:
            return vulns

        for secret_name, regex in REGEX_SECRETS.items():
            matches = re.findall(regex, html)
            for m in matches:
                evidence = m[0] if isinstance(m, tuple) else m
                # Truncate long secrets for the report
                display_evidence = f"{evidence[:20]}..." if len(evidence) > 20 else evidence

                vulns.append(Vulnerability(
                    type="JS Secret Leak",
                    url=url,
                    evidence=f"{secret_name}: {display_evidence}",
                    severity="High"
                ))
        return vulns
