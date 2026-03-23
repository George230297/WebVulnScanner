import aiohttp
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from webvulnscanner.utils.decorators import audit_log, retry_network

logger = logging.getLogger(__name__)

# Global session and semaphore for limiting concurrency
_session: Optional[aiohttp.ClientSession] = None
_semaphore: Optional[asyncio.Semaphore] = None

@dataclass
class ProbeResponse:
    status: int
    text: str
    headers: Optional[Dict[str, str]] = field(default_factory=dict)

def init_network(max_tasks: int = 50, timeout_seconds: int = 10, keepalive_timeout: int = 30) -> None:
    """
    Inicializa la sesión global aiohttp y el semáforo para limitar la concurrencia.
    Debe ser llamado al inicio del escaneo (ej. en engine.py).
    """
    global _session, _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(max_tasks)
    
    if _session is None:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds, connect=5)
        # Limit connections automatically through the TCPConnector for keep-alive benefits
        connector = aiohttp.TCPConnector(
            limit=max_tasks, 
            keepalive_timeout=keepalive_timeout,
            ssl=False # Modificar si se quiere validación estricta SSL
        )
        _session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        logger.info(f"[NETWORK] Core asíncrono inicializado: max_tasks={max_tasks}, timeout={timeout_seconds}s")

async def close_network() -> None:
    """Cierra la sesión global del cliente HTTP al finalizar el escaneo."""
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None
        logger.info("[NETWORK] Sesión asíncrona cerrada.")

@audit_log
@retry_network
async def async_request(url: str, method: str = "GET", payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, **kwargs) -> ProbeResponse:
    """
    Función base asíncrona que todos los módulos deben utilizar.
    Usa el ClientSession global y limita peticiones simultáneas con asyncio.Semaphore.
    
    Args:
        url: La URL destino.
        method: Método HTTP (GET, POST, etc).
        payload: Diccionario mapeado a formato JSON (para POST/PUT).
        params: Diccionario de query params para el URL (para GET).
        kwargs: Parámetros adicionales (headers, etc.) para aiohttp.ClientSession.request.
        
    Returns:
        ProbeResponse con el estatus HTTP, texto de respuesta y cabeceras.
    """
    
    # Auto-inicialización segura en caso de que un módulo llame esto directamente antes de init_network()
    if _session is None or _semaphore is None:
        init_network()
    
    # El semáforo restringe el número de corrutinas intentando hacer peticiones TCP concurrentemente
    async with _semaphore: # type: ignore
        try:
            # Acoustic Fragmentation (Transfer-Encoding: chunked)
            # aiohttp maneja chunked si se le pasa chunked=True, esencial para Bypass WAF L7.
            if kwargs.pop('chunked_evasion', False):
                kwargs['chunked'] = True
                
            # Despacho Inteligente de Payload: Respetamos 'data' como Form-Urlencoded
            # y 'payload' como Application/JSON puro.
            request_kwargs = {"params": params}
            if payload:
                request_kwargs["json"] = payload
            request_kwargs.update(kwargs)
            
            async with _session.request(method, url, **request_kwargs) as response: # type: ignore
                try:
                    # Security Limit: Max 5MB per Request to prevent OOM DOS
                    raw_bytes = await response.content.read(5 * 1024 * 1024)
                    text = raw_bytes.decode(response.get_encoding() or 'utf-8', errors='replace')
                except Exception as e:
                    logger.debug(f"[NETWORK] Falla descodificando respuesta de {url}: {e}")
                    text = ""
                
                return ProbeResponse(
                    status=response.status,
                    text=text,
                    headers=dict(response.headers)
                )

        except asyncio.TimeoutError:
            # Error de timeout de la petición, registramos sin detener la ejecución de otras tareas.
            logger.warning(f"[NETWORK] Timeout al contactar {url} ({method})")
            return ProbeResponse(status=0, text="Request Timeout", headers={})

        except aiohttp.ClientError as e:
            # Errores de cliente HTTP a nivel TCP, DNS, Connection Reset, etc.
            logger.error(f"[NETWORK] Error de cliente conectando a {url} ({method}): {e}")
            return ProbeResponse(status=0, text=f"Client Error: {str(e)}", headers={})

        except Exception as e:
            # Cualquier otra excepción impredecible.
            logger.critical(f"[NETWORK] Error inesperado en petición async_request -> {url}: {e}")
            return ProbeResponse(status=0, text=f"Unexpected Error: {str(e)}", headers={})

# Alias o wrapper para mantener temporalmente la compatibilidad con el resto del código no migrado.
async def send_probe(url: str, payload: Optional[Dict[str, Any]] = None, method: str = "POST", params: Optional[Dict[str, Any]] = None, **kwargs) -> ProbeResponse:
    """Wrapper Legacy para asegurar compatibilidad con código no refactorizado."""
    return await async_request(url=url, method=method, payload=payload, params=params, **kwargs)
