import asyncio
import logging
from typing import List, Dict, Any, Optional
import time

from webvulnscanner.config import ScanConfig
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.plugins import NETWORK_PLUGINS

logger = logging.getLogger("WebVulnScanner")

class AsyncNetworkScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config: ScanConfig = config
        self.ip: str = config.ip_target or ""
        self.ports_to_scan: List[int] = config.ports
        self.ports_scanned_count: int = 0
        self.open_ports: List[int] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(config.concurrency)
        
        self.plugins = [plugin_cls() for plugin_cls in NETWORK_PLUGINS]

    async def __aenter__(self) -> "AsyncNetworkScanner":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    async def check_port(self, port: int) -> None:
        async with self.semaphore:
            # Stealth: Añadir delay/jitter para evitar detección agresiva
            if getattr(self.config, 'evasion_level', 0) > 0:
                await asyncio.sleep(0.1)
                
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.ip, port), timeout=1.5
                )
                self.open_ports.append(port)
                logger.info(f"[+] Puerto abierto detectado: {port}")
                writer.close()
                await writer.wait_closed()
                
                # Ejecutar plugins específicos para este puerto
                await self.run_plugins(port)
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            finally:
                self.ports_scanned_count += 1

    async def scan_ports(self) -> None:
        logger.info(f"[*] Iniciando escaneo de red a {self.ip} ({len(self.ports_to_scan)} puertos)")
        
        tasks = [asyncio.create_task(self.check_port(port)) for port in self.ports_to_scan]
        
        if tasks:
            await asyncio.gather(*tasks)
            
        logger.info(f"[*] Escaneo de puertos finalizado. {len(self.open_ports)} puertos abiertos encontrados.")

    async def run_plugins(self, port: int) -> None:
        if not self.plugins:
            return
            
        logger.debug(f"[*] Ejecutando plugins de red para {self.ip}:{port}")
        
        tasks = [
            asyncio.create_task(plugin.check_service(self.ip, port))
            for plugin in self.plugins
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list) and r:
                for vuln in r:
                    logger.info(f"[!] Vulnerabilidad de red encontrada: {vuln.type} en {vuln.url}:{vuln.port}")
                self.vulnerabilities.extend(r)
            elif isinstance(r, Exception):
                logger.error(f"[!] Plugin error: {r}")
