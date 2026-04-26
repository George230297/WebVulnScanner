import asyncio
import aiohttp
import re
import logging
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl
from typing import Set, List, Dict, Optional, Any, Tuple

from webvulnscanner.config import ScanConfig, DEFAULT_HEADERS, SENSITIVE_FILES, REGEX_ENDPOINTS
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.plugins import ALL_PLUGINS

logger = logging.getLogger("WebVulnScanner")


class AsyncScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config: ScanConfig = config
        self.visited: Set[str] = set()
        self.js_files_scanned: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints_found: List[Dict[str, Any]] = []
        self.discovered_technologies: List[Dict[str, Any]] = []
        self.soft_404_profile = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(config.concurrency)
        self.base_domain: str = urlparse(config.start_url).netloc
        
        # Stateful Scanning Binding via Global Singleton
        from webvulnscanner.core.session_manager import global_session
        if self.config.auth_jwt:
            global_session.set_jwt(self.config.auth_jwt)
        if self.config.auth_cookie:
            global_session.load_raw_cookie(self.config.auth_cookie)
            
        # Initialize plugins dynamically via the plugin loader
        self.plugins = [plugin_cls() for plugin_cls in ALL_PLUGINS]

        from webvulnscanner.utils.encoder import encoder
        encoder.level = getattr(self.config, 'evasion_level', 0)

        # SSL context — always use the default validated context
        self.ssl_context: ssl.SSLContext = ssl.create_default_context()

    async def __aenter__(self) -> "AsyncScanner":
        import webvulnscanner.core.network as net
        net.init_network(self.config.concurrency)
        self.session = net._session
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        import webvulnscanner.core.network as net
        await net.close_network()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
    ) -> Tuple[str, int, str, Dict[str, str]]:
        from webvulnscanner.core.session_manager import global_session
        from webvulnscanner.core.stealth import global_stealth
        from webvulnscanner.core.network import async_request

        auth_kwargs = global_session.get_auth_kwargs()
        headers = auth_kwargs.get('headers', {})
        for k, v in DEFAULT_HEADERS.items():
            if k not in headers:
                headers[k] = v
        auth_kwargs['headers'] = headers

        async with self.semaphore:
            try:
                # Disparar mediante StealthManager (Rotate UA + Jitter + WAF Backoff)
                # Envoltura anti-DDoS y mitigación L7
                probe = await global_stealth.execute_with_stealth(
                    async_request,
                    url=url,
                    method=method,
                    payload=data if isinstance(data, dict) else None,
                    params=params,
                    **auth_kwargs
                )
                
                status = probe.status
                text = probe.text
                resp_headers = probe.headers or {}

                # ThreatIntel: Recolección pasiva de tecnologías targeteadas
                server_header = resp_headers.get('Server', '')
                if server_header and '/' in server_header:
                    parts = server_header.split('/')
                    tech = parts[0]
                    version = parts[1].split(' ')[0]
                    if not any(d['tech'] == tech and d['version'] == version for d in self.discovered_technologies):
                        self.discovered_technologies.append({"target": urlparse(url).netloc, "tech": tech, "version": version})

                # SessionManager: Rastreo pasivo de Tokens CSRF en respuestas limpias
                if status == 200 and method == "GET" and text:
                    global_session.extract_csrf_token(text, method="regex")

                return url, status, text, resp_headers
            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
                return url, 0, "", {}

    async def crawl_loop(self) -> None:
        from webvulnscanner.utils.soft_404_profiler import calibrate_target
        logger.info("[*] Calibrando heurística de evasión de fakes (Soft 404 Profiler)...")
        # Calibración inicial ejecutada en thread para no asfixiar el asyncio loop
        self.soft_404_profile = await asyncio.to_thread(calibrate_target, self.config.start_url)
        
        queue: asyncio.Queue[str] = asyncio.Queue()
        queue.put_nowait(self.config.start_url)

        # 1. WAF Check (blocking — important to know early)
        await self.check_waf()

        # 2. Sensitive Files scan (background task — BUG-12 FIX: tracked and awaited at end)
        sensitive_task: asyncio.Task[None] = asyncio.create_task(self.check_sensitive_files())

        # 3. Main crawl loop
        while not queue.empty() and len(self.visited) < self.config.max_pages:
            tasks: List[asyncio.Task[None]] = []
            count = min(queue.qsize(), self.config.concurrency)
            for _ in range(count):
                url = await queue.get()
                if url not in self.visited:
                    tasks.append(asyncio.create_task(self.process_url(url, queue)))

            if tasks:
                await asyncio.gather(*tasks)

        # BUG-12 FIX: ensure the background sensitive-files task finishes before we return
        await sensitive_task

        # POST-PROCESS: Aplicando Threat Intelligence a nivel asíncrono sobre tecnologías detectadas
        if self.discovered_technologies:
            logger.info("[*] Escaneo profundo finalizado. Resolviendo bases de datos CTI...")
            from webvulnscanner.core.threat_intel import threat_enricher
            await threat_enricher.enrich_findings_batch(self.discovered_technologies)
            
            for tech in self.discovered_technologies:
                for cve in tech.get('cves', []):
                    self.vulnerabilities.append(Vulnerability(
                        type=f"Threat Intel: {tech['tech']} {tech['version']}",
                        url=tech['target'],
                        evidence=f"CVE Encontrado: {cve['id']} - {cve['description']}",
                        severity=cve['severity']
                    ))

    async def check_waf(self) -> None:
        logger.info("[*] Comprobando WAF...")
        try:
            _, status, _, _ = await self.fetch(self.config.start_url, params={'q': '<script>alert(1)</script>'})
            if status == 403:
                logger.warning("[!] ADVERTENCIA: Posible WAF detectado (403 Forbidden).")
        except Exception as e:
            logger.debug(f"[WAF] Validación fallida por error transitorio: {e}")

    async def check_sensitive_files(self) -> None:
        base_url = f"{urlparse(self.config.start_url).scheme}://{self.base_domain}"

        async def check(filename: str) -> None:
            target = urljoin(base_url + '/', filename)
            _, status, html, _ = await self.fetch(target)
            
            if status == 200:
                is_false_pos = False
                
                # Nivel 1: Validación Heurística Avanzada por Extensión y Firmas Front-End
                from webvulnscanner.utils.sensitive_file_validator import is_real_sensitive_file
                if not is_real_sensitive_file(status_code=status, response_text=html, file_path=target):
                    is_false_pos = True
                
                # Nivel 2: Bypass dinámico del Soft 404 Profiler original
                if not is_false_pos and self.soft_404_profile:
                    from webvulnscanner.utils.soft_404_profiler import is_soft_404
                    class MockResp:
                        status_code = status
                        text = html
                    is_false_pos = is_soft_404(MockResp(), self.soft_404_profile)
                
                if not is_false_pos:
                    self.vulnerabilities.append(Vulnerability(
                        type="Sensitive File",
                        url=target,
                        evidence=f"Exposed {filename}",
                        severity="High"
                    ))

        await asyncio.gather(*[check(f) for f in SENSITIVE_FILES])

    async def process_url(self, url: str, queue: asyncio.Queue[str]) -> None:
        if url in self.visited:
            return
        self.visited.add(url)

        real_url, status, html, headers = await self.fetch(url)
        if status != 200 or not html:
            return

        real_url_str = str(real_url)

        # Activación Playwright DOM Parser para React/Vue SPAs detectados heurísticamente
        if '<div id="root">' in html or '<div id="app">' in html or '<script type="module"' in html:
            try:
                from webvulnscanner.core.browser import render_dynamic_page
                logger.info(f"[*] SPA detectada en {url}. Despertando Playwright Renderer...")
                rendered_html = await render_dynamic_page(real_url_str)
                if rendered_html:
                    html = rendered_html
            except ImportError:
                logger.warning(f"[*] SPA detectada en {url}, pero 'playwright' no se encuentra instalado en este entorno. Omitiendo renderizado dinámico (Fallback Estático).")

        # Discovery: follow <a> links within the same domain
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            link = urljoin(real_url_str, str(a['href']))
            if urlparse(link).netloc == self.base_domain and link not in self.visited:
                queue.put_nowait(link)

        # Advanced DAST: Extract and fuzz HTML <form>s natively
        for form in soup.find_all('form'):
            action = form.get('action') or ''
            method = form.get('method', 'get').lower()
            form_url = urljoin(real_url_str, action)
            
            # Extract expected parameters
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                # Give a default fuzzer-friendly testing value if empty
                val = inp.get('value', '1')
                form_data[name] = val
                
            if urlparse(form_url).netloc == self.base_domain:
                if method == 'post':
                    # Dispatch extracted POST forms directly to plugins
                    logger.info(f"[*] Formulario POST descubierto: {form_url} | Inputs: {list(form_data.keys())}")
                    await self.run_plugins(form_url, html="", headers=headers, form_data=form_data)
                elif method == 'get':
                    # If it's a GET form, encode the inputs into the URL and queue it natively
                    import urllib.parse
                    get_url = f"{form_url}?{urllib.parse.urlencode(form_data)}"
                    if get_url not in self.visited:
                        queue.put_nowait(get_url)

        # Discovery: find and process <script src="..."> files (JS SAST)
        scripts = [
            urljoin(real_url_str, str(s.get('src')))
            for s in soup.find_all('script')
            if s.get('src')
        ]
        for s in scripts:
            if urlparse(s).netloc == self.base_domain and s not in self.js_files_scanned:
                asyncio.create_task(self.process_js(s, queue))

        # Run all plugins against this URL
        await self.run_plugins(real_url_str, html, headers)

    async def process_js(self, js_url: str, queue: asyncio.Queue[str]) -> None:
        if js_url in self.js_files_scanned:
            return
        self.js_files_scanned.add(js_url)

        _, status, content, _ = await self.fetch(js_url)
        if status != 200 or not content:
            return

        # BUG-5 FIX: guard session before passing to plugins
        if not self.session:
            return

        # Run JS-capable plugins (e.g. SecretsCheck)
        for plugin in self.plugins:
            if hasattr(plugin, 'check_js'):
                res = await plugin.check_js(self.session, js_url, html=content)  # type: ignore[attr-defined]
                if res:
                    self.vulnerabilities.extend(res)
            elif plugin.name == "Secrets & Tokens":
                res = await plugin.check(self.session, js_url, html=content)
                self.vulnerabilities.extend(res)

        # Discovery: extract hidden API endpoints from JS source
        found_paths = re.findall(REGEX_ENDPOINTS, content)
        for path in found_paths:
            if not path.endswith(('.png', '.jpg', '.svg', '.css', '.woff')):
                full_url = urljoin(js_url, path)
                if urlparse(full_url).netloc == self.base_domain and full_url not in self.visited:
                    try:
                        queue.put_nowait(full_url)
                    except asyncio.QueueFull:
                        pass
                    except Exception as e:
                        logger.error(f"[JS_PARSER] Falla encolando ruta {full_url}: {e}")

    async def run_plugins(self, url: str, html: str, headers: Dict[str, str], form_data: Optional[Dict[str, Any]] = None) -> None:
        parsed = urlparse(url)
        params: Dict[str, Any] = dict(parse_qsl(parsed.query))

        # Advanced DAST: Heurística de Blind Parameter Fuzzing
        # Si un endpoint (ej. API REST /rest/products/search extraído de un JS) no expuso 
        # sus llaves, inyectamos campos genéricos altamente vulnerables para forzar a 
        # los módulos XSS/SQLi a probar suerte (Parameter Guessing).
        if not params and not form_data:
            url_lower = url.lower()
            if 'login' in url_lower or 'auth' in url_lower:
                form_data = {'email': 'test@test.com', 'password': 'test', 'username': 'admin'}
            elif 'search' in url_lower or 'query' in url_lower or 'find' in url_lower:
                params = {'q': 'test', 'search': 'test', 'query': 'test'}
            else:
                # Fallback base genérico para cualquier otro endpoint
                params = {'id': '1', 'q': 'test', 'page': '1', 'url': 'http://127.0.0.1'}

        logger.debug(f"Running plugins for {url} with GET params {params} and POST data {form_data}")

        # BUG-5 FIX: ensure session is available before dispatching plugins
        if not self.session:
            logger.warning("run_plugins called without an active session; skipping.")
            return

        tasks: List[asyncio.Task[List[Vulnerability]]] = [
            asyncio.create_task(plugin.check(self.session, url, html, headers, params=params, data=form_data))
            for plugin in self.plugins
        ]

        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                for vuln in r:
                    logger.info(f"[!] Vulnerability found: {vuln.type} at {vuln.url}")
                self.vulnerabilities.extend(r)

        # Track visited endpoint
        if form_data:
            self.endpoints_found.append({"url": url, "method": "POST", "params": list(form_data.keys())})
        else:
            self.endpoints_found.append({"url": url, "method": "GET", "params": list(params.keys())})
