from typing import List
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.config import XSS_PAYLOADS

class XSSCheck(BaseCheck):
    name = "Reflected XSS"

    async def check(self, session, url, html="", headers=None, params=None) -> List[Vulnerability]:
        vulns = []
        if not params:
            return vulns

        for k in params:
            for p in XSS_PAYLOADS:
                # Construct query
                p_mod = params.copy()
                p_mod[k] = p
                
                try:
                    async with session.get(url, params=p_mod) as resp:
                        text = await resp.text(errors='ignore')
                        if p in text:
                            # Confirm XSS
                            vulns.append(Vulnerability(
                                type="Reflected XSS",
                                url=str(resp.url),
                                param=k,
                                evidence=p,
                                severity="High"
                            ))
                            # Break inner loop to avoid spamming same param
                            break
                except Exception:
                    pass
        
        return vulns
