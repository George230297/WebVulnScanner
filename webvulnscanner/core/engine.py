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
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(config.concurrency)
        self.base_domain: str = urlparse(config.start_url).netloc

        # Initialize plugins dynamically via the plugin loader
        self.plugins = [plugin_cls() for plugin_cls in ALL_PLUGINS]

        # SSL context — always use the default validated context
        self.ssl_context: ssl.SSLContext = ssl.create_default_context()

    async def __aenter__(self) -> "AsyncScanner":
        timeout = aiohttp.ClientTimeout(total=20)
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        self.session = aiohttp.ClientSession(
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            connector=connector
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.session:
            await self.session.close()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
    ) -> Tuple[str, int, str, Dict[str, str]]:
        async with self.semaphore:
            try:
                if not self.session:
                    raise RuntimeError("Session not initialized. Use AsyncScanner as a context manager.")

                # Manually construct URL to prevent aiohttp from over-encoding payloads (e.g. 1')
                if params:
                    from urllib.parse import urlencode, urlunparse
                    parsed_url = urlparse(url)
                    query_string = urlencode(params, doseq=True)
                    url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment,
                    ))

                async with self.session.request(method, url, data=data, allow_redirects=True) as resp:
                    try:
                        text = await resp.text()
                    except UnicodeDecodeError:
                        text = await resp.text(errors='replace')

                    return str(resp.url), resp.status, text, dict(resp.headers)

            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
                return url, 0, "", {}

    async def crawl_loop(self) -> None:
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

    async def check_waf(self) -> None:
        logger.info("[*] Comprobando WAF...")
        try:
            _, status, _, _ = await self.fetch(self.config.start_url, params={'q': '<script>alert(1)</script>'})
            if status == 403:
                logger.warning("[!] ADVERTENCIA: Posible WAF detectado (403 Forbidden).")
        except Exception:
            pass

    async def check_sensitive_files(self) -> None:
        base_url = f"{urlparse(self.config.start_url).scheme}://{self.base_domain}"

        async def check(filename: str) -> None:
            target = urljoin(base_url + '/', filename)
            _, status, _, _ = await self.fetch(target)
            if status == 200:
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

        # Discovery: follow <a> links within the same domain
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            link = urljoin(real_url_str, str(a['href']))
            if urlparse(link).netloc == self.base_domain and link not in self.visited:
                queue.put_nowait(link)

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
                    except Exception:
                        pass

    async def run_plugins(self, url: str, html: str, headers: Dict[str, str]) -> None:
        parsed = urlparse(url)
        params: Dict[str, Any] = dict(parse_qsl(parsed.query))

        logger.debug(f"Running plugins for {url} with params {params}")

        # BUG-5 FIX: ensure session is available before dispatching plugins
        if not self.session:
            logger.warning("run_plugins called without an active session; skipping.")
            return

        tasks: List[asyncio.Task[List[Vulnerability]]] = [
            asyncio.create_task(plugin.check(self.session, url, html, headers, params))
            for plugin in self.plugins
        ]

        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                for vuln in r:
                    logger.info(f"[!] Vulnerability found: {vuln.type} at {vuln.url}")
                self.vulnerabilities.extend(r)

        # Track visited endpoint
        self.endpoints_found.append({"url": url, "method": "GET", "params": list(params.keys())})
