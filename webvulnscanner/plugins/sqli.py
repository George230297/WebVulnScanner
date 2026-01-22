from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import SQL_ERRORS

class SQLiCheck(BaseCheck):
    name = "Error-Based SQLi"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not params:
            return vulns

        for k in params:
            p_mod = params.copy()
            p_mod[k] = "1'"
            
            try:
                async with session.get(url, params=p_mod) as resp:
                    text = (await resp.text(errors='ignore')).lower()
                    
                    found_error = next((err for err in SQL_ERRORS if err in text), None)
                    if found_error:
                        vulns.append(Vulnerability(
                            type="SQLi Error-Based",
                            url=str(resp.url),
                            param=k,
                            evidence=f"DB Error triggered: {found_error}",
                            severity="Critical"
                        ))
            except Exception:
                pass
        
        return vulns
