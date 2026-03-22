import os
import asyncio
import logging
import random
from typing import Dict, Optional, Callable, Awaitable, Any, List
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

        # Phase 4: Pool de Proxies
        self.proxies: List[str] = self._load_proxies()

    def _load_proxies(self) -> List[str]:
        proxy_file = os.path.join(os.getcwd(), 'proxies.txt')
        if not os.path.exists(proxy_file):
            return []
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                # Format: ip:port
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"[STEALTH] Error cargando proxies.txt: {e}")
            return []

    def get_random_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def remove_proxy(self, proxy: str) -> None:
        if proxy in self.proxies:
            self.proxies.remove(proxy)
            logger.warning(f"[STEALTH] Proxy quemado por WAF (403/429) y descartado del pool: {proxy}")

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
        
        # 1. Rotación de cabeceras (User-Agent Spoofer) y Spoofing de IP
        headers = kwargs.get('headers', {})
        if isinstance(headers, dict): 
            # Verifica variaciones de diccionarios insensibles a mayúsculas
            if not any(k.lower() == 'user-agent' for k in headers.keys()):
                headers['User-Agent'] = self.get_random_user_agent()
            
            # Header Spoofing (Bypassing WAF IP Checks by forging internal IPs)
            spoofed_ip = "127.0.0.1"
            headers['X-Forwarded-For'] = spoofed_ip
            headers['X-Originating-IP'] = spoofed_ip
            headers['Client-IP'] = spoofed_ip
            headers['X-Remote-IP'] = spoofed_ip
            headers['X-Real-IP'] = spoofed_ip
            
            kwargs['headers'] = headers

        # Selección de proxy inicial dinámico
        current_proxy = self.get_random_proxy()
        if current_proxy:
            kwargs['proxy'] = f"http://{current_proxy}"

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

                # REFRESH IN-FLIGHT COOKIES: Si otro hilo resolvió un desafío (Cloudflare) 
                # mientras esperábamos el Lock, absorbemos sus cookies para este reintento sin hacer otro desafío.
                from webvulnscanner.core.session_manager import global_session
                if global_session._cookies:
                    kwargs['cookies'] = kwargs.get('cookies', {})
                    kwargs['cookies'].update(global_session._cookies)

                # Ejecuta la inyección real HTTP contra el target L7
                response = await request_coroutine(url, *args, **kwargs)
                
                status_code = getattr(response, "status", 0)

                # Si NO tuvimos un comportamiento L7 anti-bot (OJO: Un 404 es exitoso bajo este paradigma)
                if status_code not in (429, 403):
                    if penalty.fails > 0:
                        logger.info(f"[STEALTH] ¡WAF Evadido o Rate Limit reiniciado para {domain}! Resumiendo ataques.")
                        penalty.fails = 0 # Sanar al subdominio
                    return response

                # Auto-Healing: Si hay proxy y detona 403 o 429, el proxy está quemado. Lo rotamos y reintentamos.
                if current_proxy and status_code in (403, 429):
                    self.remove_proxy(current_proxy)
                    current_proxy = self.get_random_proxy()
                    if current_proxy:
                        kwargs['proxy'] = f"http://{current_proxy}"
                        continue # Reintenta de inmediato en el bucle principal con el nuevo proxy

                # Intercepción Definitiva de WAF (Cloudflare/Datadog JS Challenge)
                if status_code in (403, 503):
                    server_hdr = getattr(response, 'headers', {}).get('Server', '').lower()
                    text_lower = getattr(response, 'text', '').lower()
                    
                    is_cloudflare = any(kw in server_hdr or kw in text_lower for kw in ['cloudflare', 'ddos-guard', 'cf-browser-verification', 'turnstile'])
                    
                    if is_cloudflare and current_try == 0 and penalty.fails == 0:
                        logger.warning(f"[STEALTH] Bloqueo JS detectado ({status_code}) en {domain}. Derivando a Playwright Solver...")
                        try:
                            from webvulnscanner.core.browser import solve_cloudflare_challenge
                            solver_result = await solve_cloudflare_challenge(url)
                            
                            if solver_result and solver_result.get('cookies'):
                                # Inyectar cookies (ej. cf_clearance) en el motor transversal para futuras peticiones
                                for k, v in solver_result['cookies'].items():
                                    global_session._cookies[k] = v
                                    
                                # Alinear firma UA con la sesión Playwright evadida
                                if solver_result.get('user_agent'):
                                    kwargs['headers'] = kwargs.get('headers', {})
                                    kwargs['headers']['User-Agent'] = solver_result['user_agent']
                                
                                # Actualizar explícitamente el paquete asíncrono actual y reintentar
                                kwargs['cookies'] = kwargs.get('cookies', {})
                                kwargs['cookies'].update(solver_result['cookies'])
                                
                                logger.info(f"[STEALTH] Inyección exitosa de Clearance Cookies. Bypasseando bloqueo...")
                                continue # Volver a peticionar en la capa asyncio sana
                                
                        except ImportError:
                            logger.error("[STEALTH] El módulo 'playwright' no está instalado de cara al Solver. (Ejecuta: pip install -r requirements.txt)")
                        except Exception as e:
                            logger.debug(f"[STEALTH] Error crítico invocando Solver interno: {e}")

                # Un baneo fue detectado (429 'Too Many Requests' por exceso de peticiones 
                # o repentino 403 'Forbidden' originando la acumulación)
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
