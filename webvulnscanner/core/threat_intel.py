import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

class ThreatIntelProvider(ABC):
    """
    Clase abstracta pura para proveedores de Threat Intelligence.
    Garantiza que el escáner pueda conectarse en el futuro a bases de datos locales 
    (ej. un SQLite interno con VulnDB) o a APIs propietarias.
    """
    @abstractmethod
    async def query_cves(self, technology: str, version: str) -> List[Dict[str, Any]]:
        """
        Consulta información de CVEs o vulnerabilidades conocidas
        para una tecnología y versión específicas.
        Retorna una lista de diccionarios con metadatos del CVE.
        """
        pass

class PublicThreatProfiler(ThreatIntelProvider):
    """
    Ejemplo de proveedor público de Threat Intelligence (mock/plantilla).
    Se conectaría a una API abierta como NVD, Vulners, Mitre, etc.
    """
    async def query_cves(self, technology: str, version: str) -> List[Dict[str, Any]]:
        # Aquí iría el código real de aiohttp conectando a una API
        # Simulamos latencia de red de una API pública
        await asyncio.sleep(1.0) 
        
        # Respuesta simulada por motivos demostrativos
        logger.debug(f"[THREAT_INTEL] Resolviendo base de datos remota para {technology} {version}...")
        if technology.lower() == "nginx" and version == "1.18.0":
            return [{"id": "CVE-2021-23017", "severity": "HIGH", "description": "1-byte memory overwrite in resolver"}]
        elif technology.lower() == "apache" and version == "2.4.49":
            return [{"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Path traversal and file disclosure"}]
        return []

class ThreatIntelEnricher:
    """
    Módulo de fase de post-procesamiento. Toma los datos recolectados
    durante el escaneo activo y los enriquece de forma asíncrona usando caché.
    """
    def __init__(self, provider: ThreatIntelProvider):
        self.provider = provider
        # Patrón de Caché explícito en memoria (Diccionario thread-safe por GIL)
        # Llave: Tupla (tecnología, versión), Valor: Resultado de la API (Lista de CVEs)
        self._cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        # Semáforo para no saturar APIs públicas en enriquecimientos masivos
        self._api_semaphore = asyncio.Semaphore(5)
        # Lock de deduplicación para requests idénticos en vuelo
        self._inflight_locks: Dict[Tuple[str, str], asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _fetch_with_cache(self, technology: str, version: str) -> List[Dict[str, Any]]:
        cache_key = (technology.lower(), version.lower())
        
        # 1. Caché inmediato (Hit)
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        # 2. Manejo de peticiones "en vuelo" (In-flight request deduplication)
        # Evita que 50 subdominios con 'Apache 2.4' disparen 50 peticiones a la API
        # al mismo milisegundo antes de que la primera termine y pueble la caché.
        async with self._global_lock:
            if cache_key not in self._inflight_locks:
                self._inflight_locks[cache_key] = asyncio.Lock()
        
        inflight_lock = self._inflight_locks[cache_key]
        
        async with inflight_lock:
            # Double-check pattern tras adquirir el lock
            if cache_key in self._cache:
                return self._cache[cache_key]
                
            # 3. Cache Miss - Consultar al proveedor (concurrencia limitada)
            try:
                async with self._api_semaphore:
                    results = await self.provider.query_cves(technology, version)
                
                # Poblar la caché para futuros usos
                self._cache[cache_key] = results
                logger.info(f"[THREAT_INTEL] Caché actualizado para {technology} {version} ({len(results)} CVEs reportados)")
                return results
            except Exception as e:
                logger.error(f"[THREAT_INTEL] Error de API consultando inteligencia para {technology} {version}: {e}")
                return []
            finally:
                # Limpiamos el lock en vuelo
                async with self._global_lock:
                    if cache_key in self._inflight_locks:
                        del self._inflight_locks[cache_key]

    async def enrich_findings_batch(self, discovered_technologies: List[dict]) -> None:
        """
        Punto de entrada para la fase de post-procesamiento.
        Recibe una lista de hallazgos del escáner y los resuelve concurrentemente
        en tarea separada, sin interferir con la red activa.
        
        [
            {"target": "sub1.domain.com", "tech": "Nginx", "version": "1.18.0"},
            {"target": "sub2.domain.com", "tech": "Apache", "version": "2.4.49"},
            {"target": "sub3.domain.com", "tech": "Nginx", "version": "1.18.0"}
        ]
        """
        logger.info(f"[THREAT_INTEL] Iniciando enriquecimiento asíncrono en post-procesamiento de {len(discovered_technologies)} nodos.")
        
        # Crear corrutinas de forma paralela
        tasks = []
        for finding in discovered_technologies:
            tech = finding.get("tech")
            ver = finding.get("version")
            if tech and ver:
                # Adjuntamos la tarea a la lista (no la bloqueamos con await aún)
                tasks.append(self._enrich_single_finding(finding, tech, ver))
                
        # Lanzar todas las corrutinas concurrentemente
        await asyncio.gather(*tasks)
        
        logger.info("[THREAT_INTEL] Fase de post-procesamiento finalizada.")

    async def _enrich_single_finding(self, finding: dict, technology: str, version: str) -> None:
        """Actualiza el diccionario original del hallazgo con los CVEs descubiertos."""
        cves = await self._fetch_with_cache(technology, version)
        if cves:
            finding["cves"] = cves

# Inicialización pre-fabricada para el engine
# engine.py podrá inyectar sus propios providers si es necesario.
default_provider = PublicThreatProfiler()
threat_enricher = ThreatIntelEnricher(provider=default_provider)
