import os
from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.core.network import send_probe


class XSSCheck(BaseCheck):
    """Checks for Reflected Cross-Site Scripting vulnerabilities."""

    @property
    def name(self) -> str:
        return "Reflected XSS"

    def __init__(self) -> None:
        self.payloads: List[str] = self._load_payloads()

    def _load_payloads(self) -> List[str]:
        payload_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'payloads',
            'xss.txt'
        )
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ['<script>alert(1)</script>']  # Fallback

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
            for p in self.payloads:
                p_mod = params.copy()
                p_mod[k] = p

                resp = await send_probe(url, method="GET", params=p_mod)
                if resp.status != 0 and p in resp.text:
                    vulns.append(Vulnerability(
                        type="Reflected XSS",
                        url=str(url),
                        param=k,
                        evidence=p,
                        severity="High"
                    ))
                    # Stop testing further payloads for this param once found
                    break

        return vulns
