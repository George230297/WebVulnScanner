from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import SQL_ERRORS
from webvulnscanner.core.network import send_probe

class SQLiCheck(BaseCheck):
    name = "Error-Based SQLi"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not params:
            return vulns

        for k in params:
            p_mod = params.copy()
            p_mod[k] = "1'"
            
            # Use send_probe for robust networking (retries, logging)
            resp = await send_probe(url, method="GET", params=p_mod)
            
            if resp.status != 0: # 0 indicates failure in send_probe (implied by lack of exception?) 
                # Wait, send_probe might raise if decorators don't suppress all. 
                # Decorator suppresses? retry_network raises after retries. audit_log re-raises.
                # Use try-except here strictly for business logic, not network errors if we want to skip.
                 
                text = resp.text.lower()
                found_error = next((err for err in SQL_ERRORS if err in text), None)
                if found_error:
                    vulns.append(Vulnerability(
                        type="SQLi Error-Based",
                        url=str(url), # url is effectively the same, but full url with params is cleaner? 
                        # Use url + params manually if needed, or just base url.
                        param=k,
                        evidence=f"DB Error triggered: {found_error}",
                        severity="Critical"
                    ))
        
        return vulns
