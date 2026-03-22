import asyncio
import logging
import random
from typing import Dict, Optional, Callable, Awaitable, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

USER_AGENTS = [
    # Colección moderna de huellas biológicas y navegadores legítimos reales
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
]

class TargetPenalty:
    """Rastrea el estado de backoff/bloqueo de memoria por dominio individual."""
    def __init__(self):
        self.lock = asyncio.Lock()
        self.fails = 0
        self.is_unreachable = False

class StealthManager:
    """
    Gestor de Evasión (Stealth Mode) de WAF y Firewalls (Capa L7).
    Modela huellas artificiales insertando:
      - 'Jitter' (Ruido estocástico/matemático) para alterar firmas de tiempo temporal.
      - Rotación dinámica y en caliente de los agentes de usuario.
      - Autoprotección de Backoff Exponencial Thread-Safe frente a baneos '429' repentinos.
    """
    def __init__(self, min_jitter: float = 0.5, max_jitter: float = 2.5, max_backoff_retries: int = 4, base_backoff_time: float = 5.0):
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self.max_backoff_retries = max_backoff_retries
        self.base_backoff_time = base_backoff_time
        
        # Diccionario para mapear hostnames (ej. "api.target.com") contra su Lock y Falla actual
        self._penalties: Dict[str, TargetPenalty] = {}
        # Global lock simple para insertar subdominios nuevos al dict de castigos de forma atómica
        self._global_dict_lock = asyncio.Lock()

    def get_random_user_agent(self) -> str:
        """Devuelve un User-Agent completamente aleatorio del Pool moderno."""
        return random.choice(USER_AGENTS)

    async def apply_jitter(self) -> None:
        """
        Retardo flotante estocástico a nivel asíncrono.
        Simula perfectamente a un atacante humano o tráfico orgánico (No-Burst).
        """
        delay = random.uniform(self.min_jitter, self.max_jitter)
        # Esto solo pausa LA ÚNICA corrutina actual, no bloquea el engine entero de escaneo global
        await asyncio.sleep(delay)

    def _get_domain(self, url: str) -> str:
        """Decodifica el FQDN o subdominio particular."""
        try:
            return urlparse(url).netloc
        except Exception:
            return "unknown-host"

    async def execute_with_stealth(self, request_coroutine: Callable[..., Awaitable[Any]], url: str, *args, **kwargs) -> Any:
        """
        Decora o envuelve una petición base inyectando evasión y reintento.
        Esta función debe envolver al 'async_request' de core/network.py.
        """
        domain = self._get_domain(url)
        
        # 1. Rotación de cabeceras (User-Agent Spoofer)
        headers = kwargs.get('headers', {})
        if isinstance(headers, dict): 
            # Verifica variaciones de diccionarios insensibles a mayúsculas
            if not any(k.lower() == 'user-agent' for k in headers.keys()):
                headers['User-Agent'] = self.get_random_user_agent()
            kwargs['headers'] = headers

        # 2. Aplicamos la ralentización de red Jitter de seguridad
        await self.apply_jitter()

        # Generar atómicamente la estructura de castigo si el dominio es virgen
        async with self._global_dict_lock:
            if domain not in self._penalties:
                self._penalties[domain] = TargetPenalty()
        
        penalty = self._penalties[domain]

        # Escape rápido: Si un Firewall ya expulsó al escáner, se omiten todas las peticiones a ese subdominio.
        if penalty.is_unreachable:
            # Devuelve una respuesta nula para no gastar recursos
            from webvulnscanner.core.network import ProbeResponse
            return ProbeResponse(status=0, text="Dominio temporalmente inalcanzable (WAF Auto-Ban en StealthManager)", headers={})

        current_try = 0
        response = None
        
        # Bucle de reintentos
        while current_try <= self.max_backoff_retries:
            # Sincronización estricta por SUBDOMINIO: Si 100 módulos están descubriendo vulns 
            # concurrentemente acá (haciendo .acquire() del mismo lock de dominio), si el servidor 
            # detona un 429, el primer hilo que atrape el error mantendrá bloqueado a los otros 99 un rato,
            # forzando el backoff exponencial, y los demás esperarán civilizadamente ahorrando un "Ban Permanente".
            async with penalty.lock:
                # Doble validación de escape para la cola concurrente estanca:
                if penalty.is_unreachable:
                    from webvulnscanner.core.network import ProbeResponse
                    return ProbeResponse(status=0, text="WAF Ban detectado durante el Backoff", headers={})

                # Ejecuta la inyección real HTTP contra el target L7
                response = await request_coroutine(url, *args, **kwargs)
                
                status_code = getattr(response, "status", 0)

                # Si NO tuvimos un comportamiento L7 anti-bot (OJO: Un 404 es exitoso bajo este paradigma)
                if status_code not in (429, 403):
                    if penalty.fails > 0:
                        logger.info(f"[STEALTH] ¡WAF Evadido o Rate Limit reiniciado para {domain}! Resumiendo ataques.")
                        penalty.fails = 0 # Sanar al subdominio
                    return response

                # Un baneo fue detectado (429 'Too Many Requests' por exceso de peticiones 
                # o repentino 403 'Forbidden' usualmente de un WAF como Cloudflare al detectar ráfagas bot)
                penalty.fails += 1
                current_try = penalty.fails
                
                # Umbral de tolerancia alcanzado, el backend quemó la IP para ese TLD/FQDN.
                if current_try > self.max_backoff_retries:
                    penalty.is_unreachable = True
                    logger.error(f"[STEALTH] Tolerancia de WAF excedida en {domain} tras {current_try} evasiones. Se marca como objetivo INALCANZABLE de por vida.")
                    return response
                
                # 3. Penalidad Lineal/Exponencial Automática (Backoff)
                # Intento 1: 5s, Intento 2: 10s, Intento 3: 20s, Intento 4: 40s.
                backoff_wait = self.base_backoff_time * (2 ** (current_try - 1))
                
                logger.warning(
                    f"[STEALTH] Detectado Filtro/WAF {status_code} ({'Rate-Limit' if status_code == 429 else 'Forbidden'}) "
                    f"en {domain}. Activando Backoff Exponencial: "
                    f"Pausando hilo subyacente {backoff_wait}s (Intento evasivo {current_try}/{self.max_backoff_retries})."
                )
                
                # Se duerme obligatoriamente toda la cola concurrente que haya atrapado el "Lock"
                await asyncio.sleep(backoff_wait)
                logger.debug(f"[STEALTH] Backoff expirado para {domain}, reintentando inyección in-band...")

        # Fallback de cierre por escape (Si rompe el while)
        return response

global_stealth = StealthManager()
