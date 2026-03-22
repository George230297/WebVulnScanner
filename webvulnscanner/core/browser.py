import asyncio
import logging
from typing import Optional
from playwright.async_api import async_playwright, Browser, Page, Error as PlaywrightError

logger = logging.getLogger(__name__)

class DynamicRenderer:
    """
    Administrador de Contexto (Context Manager) asíncrono para renderizar páginas 
    dinámicas (SPAs/React/Vue/Angular) utilizando Playwright.
    
    Garantiza estrictamente que el proceso del navegador (Chromium) se cierre, 
    evitando que queden instancias huérfanas bloqueando memoria en caso de error.
    """
    def __init__(self, headless: bool = True, timeout_ms: int = 15000):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context = None
        self.page: Optional[Page] = None

    async def __aenter__(self):
        """Inicializa Playwright y el navegador de forma controlada."""
        self.playwright = await async_playwright().start()
        # Se inicia Chromium porque suele ser el más estable y ligero para tareas headless.
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context()
        self.page = await self.context.new_page()

        # Configurar la interceptación inteligente y bloqueo de recursos
        await self.page.route("**/*", self._intercept_route)
        
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Asegura que todos los recursos se cierren y se finalicen los procesos.
        El try/finally nativo de los Context Managers lo hace 100% seguro.
        """
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
        except Exception as cleanup_error:
            logger.error(f"[BROWSER] Error limpiando recursos internos: {cleanup_error}")
        finally:
            # Siempre intentamos matar el proceso base de playwright.
            if self.playwright:
                await self.playwright.stop()

        if exc_val:
            logger.error(f"[BROWSER] Renderizado abortado por error crítico: {exc_val}")
        
        # Devuelve False para propagar la excepción hacia arriba si así se desea
        # (aunque hemos mitigado las principales dentro de render_dom)
        return False

    async def _intercept_route(self, route):
        """
        Intercepta y bloquea peticiones de Playwright de contenido no crítico.
        Esto ahorra masivamente recursos y acelera el renderizado drásticamente,
        descargando solo lo necesario para hidratar la SPA (HTML, JS, API calls).
        """
        allowed_types = {"document", "script", "xhr", "fetch"} # Elementos útiles para la ejecución base
        # Tipos que suelen bloquearse: stylesheet (css), image, media, font, manifest, websocket, etc.
        
        if route.request.resource_type in allowed_types:
            await route.continue_()
        else:
            await route.abort()

    async def render_dom(self, url: str) -> Optional[str]:
        """
        Navega a la URL, espera `networkidle` (SPA cargada y peticiones inactivadas),
        y extrae el contenido DOM final.
        """
        if not self.page:
            raise RuntimeError("El navegador del DynamicRenderer no se inicializó correctamente.")

        try:
            # wait_until='networkidle' asegura esperar a los componentes dinámicos como React useEffect()
            # el timeout protege contra cuelgues eternos por un solo script infinito de JS.
            await self.page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            
            # Obtener el html final parseado
            return await self.page.content()

        except PlaywrightError as e:
            # Es habitual que falte una conexión de tracking minoritaria, dando un error de Timeout,
            # pero la página general ya ha cargado bien. Intentamos recuperar el contenido renderizado de todas formas.
            logger.warning(f"[BROWSER] Playwright Timeout/Error parcial navegando a {url}: {e}")
            try:
                # Recuperar contenido en su estado actual, parcial o total.
                return await self.page.content()
            except Exception as backup_error:
                logger.debug(f"[BROWSER] Falló el fallback de contenido: {backup_error}")
                return None
        except Exception as e:
            logger.error(f"[BROWSER] Excepción general renderizando {url}: {e}")
            return None

async def render_dynamic_page(url: str, headless: bool = True, timeout_seconds: int = 15) -> Optional[str]:
    """
    Función base (wrapper) lista para ser utilizada en las utilidades de escaneo.
    """
    # Convertimos segundos a milisegundos para Playwright
    timeout_ms = timeout_seconds * 1000
    
    async with DynamicRenderer(headless=headless, timeout_ms=timeout_ms) as renderer:
        html_content = await renderer.render_dom(url)
        return html_content
