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
        data: Optional[Dict[str, Any]] = None,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        from webvulnscanner.utils.encoder import encoder
        
        if params:
            for k in params:
                for p in self.payloads:
                    mutated_p = encoder.apply_random_mutation(p, context="xss")
                    p_mod = params.copy()
                    p_mod[k] = mutated_p

                    resp = await send_probe(url, method="GET", params=p_mod)
                    if resp.status != 0 and (mutated_p in resp.text or p in resp.text):
                        vulns.append(Vulnerability(
                            type="Reflected XSS",
                            url=str(url),
                            param=k,
                            evidence=p,
                            severity="High"
                        ))
                        break
                        
        if data:
            for k in data:
                for p in self.payloads:
                    mutated_p = encoder.apply_random_mutation(p, context="xss")
                    d_mod = data.copy()
                    d_mod[k] = mutated_p

                    resp = await send_probe(url, method="POST", data=d_mod)
                    if resp.status != 0 and (mutated_p in resp.text or p in resp.text):
                        vulns.append(Vulnerability(
                            type="POST XSS",
                            url=str(url),
                            param=k,
                            evidence=p,
                            severity="High"
                        ))
                        break

        # Advanced DAST: Heurística Anti-DOM XSS (Headless Browser)
        # Desplegamos un navegador real fantasma solo para el parámetro GET
        # con un payload de diagnóstico rápido y barato para no colapsar la RAM.
        if params:
            try:
                from webvulnscanner.core.browser import DynamicRenderer
                import urllib.parse
                
                for k in params:
                    dom_payload = '"><script>alert("DOM-XSS")</script>'
                    p_mod = params.copy()
                    p_mod[k] = dom_payload
                    
                    parsed_url = urllib.parse.urlparse(url)
                    query = urllib.parse.urlencode(p_mod)
                    dom_test_url = parsed_url._replace(query=query).geturl()

                    # Iniciar navegador ligero solo por 5s
                    async with DynamicRenderer(headless=True, timeout_ms=5000) as renderer:
                        html, alerts = await renderer.render_dom(dom_test_url)
                        if alerts:
                            vulns.append(Vulnerability(
                                type="DOM-Based XSS",
                                url=str(url),
                                param=k,
                                evidence=f"JavaScript execution confirmed! Alert Dialog Intercepted: {alerts[0]}",
                                severity="High",
                                category="xss"
                            ))
                            break
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"[DOM-XSS] Error interno renderizando {dom_test_url}: {e}")

        return vulns
