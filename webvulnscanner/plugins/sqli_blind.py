import time
from typing import List, Optional, Dict, Any
from webvulnscanner.plugins.base import BaseCheck
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.core.network import send_probe

class SQLiBlindCheck(BaseCheck):
    """Checks for Time-Based Blind SQL Injection vulnerabilities."""

    @property
    def name(self) -> str:
        return "Time-Based Blind SQLi"

    def __init__(self) -> None:
        # We test cross-database sleep payloads (MySQL, PostgreSQL, MSSQL)
        self.payloads = [
            "1' WAITFOR DELAY '0:0:5'--",
            "1 WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1'; pg_sleep(5)--",
            "1; pg_sleep(5)--"
        ]
        self.delay_threshold = 4.5  # Seconds of deviation to consider it vulnerable

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
        
        if not params and not data:
            return vulns

        # Baseline measurement: Fire a safe probe to see how fast the server naturally is
        start_time = time.time()
        safe_params = params.copy() if params else {}
        for k in safe_params: safe_params[k] = "1"
        safe_data = data.copy() if data else {}
        for k in safe_data: safe_data[k] = "1"
        
        await send_probe(url, method="POST" if data else "GET", params=safe_params, data=safe_data)
        baseline_duration = time.time() - start_time

        # TEST GET
        if params:
            for k in params:
                for p in self.payloads:
                    from webvulnscanner.utils.encoder import encoder
                    mutated_p = encoder.apply_random_mutation(p, context="sqli")
                    p_mod = params.copy()
                    p_mod[k] = mutated_p

                    start_time = time.time()
                    resp = await send_probe(url, method="GET", params=p_mod)
                    duration = time.time() - start_time

                    if resp.status != 0 and (duration - baseline_duration) >= self.delay_threshold:
                        vulns.append(Vulnerability(
                            type="Blind SQLi (Time-Based)",
                            url=str(url),
                            param=k,
                            evidence=f"Payload delayed response by {duration:.2f}s (Baseline: {baseline_duration:.2f}s)",
                            severity="Critical"
                        ))
                        break

        # TEST POST
        if data:
            for k in data:
                for p in self.payloads:
                    from webvulnscanner.utils.encoder import encoder
                    mutated_p = encoder.apply_random_mutation(p, context="sqli")
                    d_mod = data.copy()
                    d_mod[k] = mutated_p

                    start_time = time.time()
                    resp = await send_probe(url, method="POST", data=d_mod)
                    duration = time.time() - start_time

                    if resp.status != 0 and (duration - baseline_duration) >= self.delay_threshold:
                        vulns.append(Vulnerability(
                            type="Blind POST SQLi (Time-Based)",
                            url=str(url),
                            param=k,
                            evidence=f"Payload delayed response by {duration:.2f}s (Baseline: {baseline_duration:.2f}s)",
                            severity="Critical"
                        ))
                        break

        return vulns
