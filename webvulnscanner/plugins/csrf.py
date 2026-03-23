from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from urllib.parse import urljoin


class CSRFCheck(BaseCheck):
    """Heuristic check for forms missing CSRF protection tokens."""

    @property
    def name(self) -> str:
        return "CSRF Heuristic"

    async def check(
        self,
        session: Any,
        url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not html:
            return vulns

        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_str = str(form).lower()
            # Check for common CSRF token field names
            has_token = any(t in form_str for t in ['csrf', 'token', 'nonce', '_token', 'authenticity'])
            if not has_token:
                action = form.get('action') or ""
                vulns.append(Vulnerability(
                    type="Potential CSRF",
                    url=urljoin(url, action),
                    evidence="Form without CSRF token",
                    severity="Low"
                ))
        return vulns
