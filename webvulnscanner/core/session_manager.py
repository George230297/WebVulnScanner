import asyncio
import logging
import re
from typing import Dict, Optional, Callable, Awaitable, Any
from bs4 import BeautifulSoup
import aiohttp

logger = logging.getLogger(__name__)

class SessionManager:
    """
    Gestor de Estado y Sesiones para el orquestador asíncrono de WebVulnScanner.
    Maneja cookies en crudo, tokens JWT, extracción de tokens CSRF y 
    cuenta con lógica asíncrona de auto-refresh ante errores HTTP 401/403.
    """
    def __init__(self):
        self._cookies: Dict[str, str] = {}
        self._headers: Dict[str, str] = {}
        self._csrf_token: Optional[str] = None
        self._refresh_callback: Optional[Callable[[], Awaitable[bool]]] = None
        
        # Lock de concurrencia: Evita que si 50 corrutinas reciben HTTP 401 a la vez, 
        # las 50 intenten hacer login y spameen al servidor. Solo 1 lo hará.
        self._refresh_lock = asyncio.Lock()
        self._is_refreshing = False

    def load_raw_cookie(self, raw_cookie_string: str) -> None:
        """
        Inicializa la sesión desde un string estático de cookies capturado por el usuario 
        (ej: "PHPSESSID=vab34bc1; user_id=45").
        """
        self._cookies.clear()
        parts = raw_cookie_string.split(';')
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                self._cookies[k.strip()] = v.strip()
        logger.info("[SESSION] Cookies cargadas e inicializadas correctamente en el Manager global.")

    def set_jwt(self, jwt_token: str) -> None:
        """
        Inicializa la sesión inyectando un token JWT estándar en las cabeceras Authorization.
        """
        self._headers['Authorization'] = f"Bearer {jwt_token.strip()}"
        logger.info("[SESSION] Token JWT configurado globalmente para el escaneo.")

    def set_auto_refresh_callback(self, callback: Callable[[], Awaitable[bool]]) -> None:
        """
        Configura el hook/callback de Auto-Refresh.
        Debe ser una función asíncrona que re-autentique al usuario (ej. POST a /login)
        en caso de que los tokens expiren a mitad de un escaneo largo.
        Debe devolver True si tuvo éxito, False si falló.
        """
        self._refresh_callback = callback
        logger.debug("[SESSION] Callback de Auto-Refresh configurado y listo para invocar ante un 401/403.")

    def extract_csrf_token(self, html_content: str, token_name: str = "csrf_token", method: str = "bs4") -> Optional[str]:
        """
        Extrae dinámicamente un token CSRF (o similar) del HTML usando BeautifulSoup o RegEx.
        Busca atributos 'value' de campos <input type="hidden"> o etiquetas <meta>.
        
        Args:
            html_content: El HTML de una petición GET previa.
            token_name: Atributo 'name' del input/meta a buscar (ej. csrf_token, authenticity_token, _csrf).
            method: 'bs4' para un parseo robusto en HTML complejo, o 'regex' para mayor velocidad 
                    y tolerancia frente a HTML malformados.
        """
        extracted_token = None
        
        if method == "bs4":
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Búsqueda 1: Field tipo hidden
                input_tag = soup.find('input', attrs={'name': token_name})
                if input_tag and input_tag.has_attr('value'): # type: ignore
                    extracted_token = input_tag['value'] # type: ignore
                
                # Búsqueda 2: Meta tags (usado mucho en Laravel, Rails, Django)
                if not extracted_token:
                    # Convierte underscore en dash porque es el estándar para metas (ej: csrf-token)
                    meta_tag = soup.find('meta', attrs={'name': token_name.replace('_', '-')})
                    if meta_tag and meta_tag.has_attr('content'): # type: ignore
                        extracted_token = meta_tag['content'] # type: ignore
            except Exception as e:
                logger.debug(f"[SESSION] Error extrayendo CSRF con BeautifulSoup: {e}")

        elif method == "regex":
            try:
                # Patrón para el input hidden: <input type="hidden" name="csrf_token" value="abc...">
                pattern = re.compile(rf'<input[^>]+name=["\']{re.escape(token_name)}["\'][^>]+value=["\']([^"\']+)["\']', re.IGNORECASE)
                match = pattern.search(html_content)
                if match:
                    extracted_token = match.group(1)
                
                # Patrón para el meta tag: <meta name="csrf-token" content="abc...">
                if not extracted_token:
                    meta_pattern = re.compile(rf'<meta[^>]+name=["\']{re.escape(token_name.replace("_", "-"))}["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
                    meta_match = meta_pattern.search(html_content)
                    if meta_match:
                        extracted_token = meta_match.group(1)
            except Exception as e:
                logger.debug(f"[SESSION] Error extrayendo CSRF con RegEx: {e}")

        if extracted_token:
            self._csrf_token = extracted_token
            # Ocultamos la mayor parte del token por seguridad en los logs (Masking)
            visible_part = extracted_token[:6] + "..." if len(extracted_token) > 10 else "***"
            logger.info(f"[SESSION] Token CSRF '{token_name}' extraído dinámicamente y guardado: {visible_part}")
        else:
            logger.warning(f"[SESSION] Token CSRF '{token_name}' no hallado en HTML. Asumiendo modo API/SPA y continuando ejecución de plugins...")
            
        return self._csrf_token

    def get_auth_kwargs(self) -> Dict[str, Any]:
        """
        Retorna un hash (dict) con los parámetros inyectables nativos para aiohttp (headers, cookies)
        configurados para realizar peticiones autenticadas.
        """
        kwargs: Dict[str, Any] = {}
        if self._cookies:
            kwargs['cookies'] = self._cookies.copy()
        if self._headers:
            kwargs['headers'] = self._headers.copy()
            
        # Inyectar el CSRF token como header alternativo (muy común en backend APIs).
        # Si se necesita dentro de un payload x-www-form-urlencoded, se deberá inyectar aparte.
        if self._csrf_token:
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['headers']['X-CSRF-Token'] = self._csrf_token
            # Otros mapeos comunes si el admin decide probarlos por override
            kwargs['headers']['X-XSRF-TOKEN'] = self._csrf_token 
            
        return kwargs

    async def handle_auto_refresh(self, response_status: int) -> bool:
        """
        Mecanismo avanzado de Auto-Refresh para peticiones huérfanas o expiradas.
        Se invoca de forma condicional desde el network core async si recibe error de autorización.
        """
        if response_status not in (401, 403):
            # No es un error de autorización de sesión expirada
            return True
            
        if not self._refresh_callback:
            # Si se configuró para auditar zonas protegidas pero sin callback dinámico, no podemos salvar la sesión global.
            logger.warning(f"[SESSION] Respuesta HTTP {response_status} pero no hay Callback de Auto-Refresh configurado. Fallará la petición.")
            return False

        if self._is_refreshing:
            # Otra corrutina (dentro del Semaphore core async) se adelantó y ya detectó el 401. 
            # Ella está pidiéndole al callback hacer el /login de nuevo. Simplemente bloqueamos a esta 
            # corrutina colindante hasta que la líder termine la tarea.
            logger.debug("[SESSION] Esperando silenciosamente a que otra tarea concurrente termine el Auto-Refresh global...")
            async with self._refresh_lock:
                return True # Asumimos que la pionera lo salvó, se intentará de nuevo

        # Ésta corrutina adquirirá el rol protagónico para refrescar los datos para el resto del escáner
        async with self._refresh_lock:
            # Marcamos en True para frenar a las corrutinas que vengan detrás nuestra
            self._is_refreshing = True
            logger.warning(f"[SESSION] Se detectó expiración de token o sesión (HTTP {response_status}). Pausando peticiones activas e iniciando Callback de Auto-Refresh global...")
            
            try:
                # Disparamos la función asíncrona externa suministrada (el usuario/programador que hizo el script)
                success = await self._refresh_callback()
                if success:
                    logger.info("[SESSION] Auto-Refresh Exitoso. Sesión restaurada, escaneo reanudado.")
                    return True
                else:
                    logger.error("[SESSION] Callack Auto-Refresh devolvió False. Autorización muerta.")
                    return False
            except Exception as e:
                logger.error(f"[SESSION] Pánico ejecutando el Callback de Auto-Refresh: {e}")
                return False
            finally:
                # Una vez restaurado (o truncado con error letal), liberamos la puerta
                self._is_refreshing = False

# Singleton global manager para acceder desde cualquier plugin (ej. globals.session.extract_csrf_token...)
global_session = SessionManager()
