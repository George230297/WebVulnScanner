import asyncio
from typing import List
from webvulnscanner.plugins.base import BaseNetworkPlugin
from webvulnscanner.models.vulnerability import Vulnerability

class AnonymousFTPCheck(BaseNetworkPlugin):
    @property
    def name(self) -> str:
        return "Anonymous FTP Access"

    async def check_service(self, ip: str, port: int) -> List[Vulnerability]:
        if port != 21 and port != 2121:
            return []

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            
            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=1.0)
            
            # Send USER anonymous
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_resp = await asyncio.wait_for(reader.readline(), timeout=1.0)
            
            if b"331" in user_resp:
                # Send PASS empty or email
                writer.write(b"PASS anonymous@example.com\r\n")
                await writer.drain()
                pass_resp = await asyncio.wait_for(reader.readline(), timeout=1.0)
                
                if b"230" in pass_resp:
                    # Login successful
                    writer.write(b"QUIT\r\n")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    
                    return [Vulnerability(
                        type="Anonymous FTP Access",
                        url=ip,
                        port=port,
                        evidence=f"Banner: {banner.decode('utf-8', 'ignore').strip()} | Response: {pass_resp.decode('utf-8', 'ignore').strip()}",
                        severity="High",
                        category="Infrastructure"
                    )]
            
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return []
