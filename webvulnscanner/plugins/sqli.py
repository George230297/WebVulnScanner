import os
import aiohttp
from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.core.network import send_probe

class SQLiCheck(BaseCheck):
    name: str = "Error-Based SQLi"

    def __init__(self) -> None:
        self.sql_errors: List[str] = self._load_errors()

    def _load_errors(self) -> List[str]:
        payload_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'payloads',
            'sqli.txt'
        )
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            return ['syntax error', 'mysql fetch', 'unclosed quotation', 'you have an error in your sql syntax'] # Fallback

    async def check(self, session: Any, url: str, html: str = "", headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not params:
            return vulns

        for k in params:
            p_mod = params.copy()
            p_mod[k] = "1'"
            
            # Use send_probe for robust networking (retries, logging, timeouts)
            resp = await send_probe(url, method="GET", params=p_mod)
            
            # 0 indicates failure in send_probe (e.g. timeout or connection drop)
            if resp.status != 0: 
                text = resp.text.lower()
                found_error = next((err for err in self.sql_errors if err in text), None)
                if found_error:
                    vulns.append(Vulnerability(
                        type="SQLi Error-Based",
                        url=str(url),
                        param=k,
                        evidence=f"DB Error triggered: {found_error}",
                        severity="Critical"
                    ))
        
        return vulns
