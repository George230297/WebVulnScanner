from typing import List
from bs4 import BeautifulSoup
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from urllib.parse import urljoin

class CSRFCheck(BaseCheck):
    name = "CSRF Heuristic"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not html: return vulns
        
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            # Very basic check: look for inputs named 'csrf' or 'token'
            if not any(t in str(form).lower() for t in ['csrf', 'token', 'nonce']):
                 action = form.get('action') or ""
                 vulns.append(Vulnerability(
                     type="Potential CSRF", 
                     url=urljoin(url, action), 
                     evidence="Form without CSRF token", 
                     severity="Low"
                 ))
        return vulns
