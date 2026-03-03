import asyncio
import aiohttp
import re
import logging
import json
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
        
        # Initialize plugins dynamically based on the updated __init__.py loader
        self.plugins = [plugin_cls() for plugin_cls in ALL_PLUGINS]
        
        # Configure SSL context based on authorization/requirements
        self.ssl_context: ssl.SSLContext = ssl.create_default_context()
        if not self.config.authorized:
             pass
        else:
             pass

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

    async def fetch(self, url: str, method: str = "GET", params: Optional[Dict[str, Any]] = None, data: Any = None) -> Tuple[str, int, str, Dict[str, str]]:
        async with self.semaphore:
            try:
                if not self.session:
                    raise RuntimeError("Session not initialized")
                
                # Construct the full URL manually if params are provided.
                # This ensures aiohttp does not aggressive-encode payloads like 1'
                if params:
                    from urllib.parse import urlencode, urlunparse
                    parsed_url = urlparse(url)
                    # Use doseq=True to handle lists correctly even though we don't expect them
                    query_string = urlencode(params, doseq=True)
                    # Reconstruct URL without modifying aiohttp behavior
                    url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query_string, parsed_url.fragment))

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
        
        # 1. WAF Check (Blocking, important to know early)
        await self.check_waf()
        
        # 2. Sensitive Files (Start in background)
        asyncio.create_task(self.check_sensitive_files())

        # 3. Main Loop
        while not queue.empty() and len(self.visited) < self.config.max_pages:
            tasks: List[asyncio.Task[None]] = []
            # Batch processing based on concurrency and queue size
            count = min(queue.qsize(), self.config.concurrency)
            for _ in range(count):
                url = await queue.get()
                if url not in self.visited:
                    tasks.append(asyncio.create_task(self.process_url(url, queue)))
            
            if tasks:
                await asyncio.gather(*tasks)

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
        if url in self.visited: return
        self.visited.add(url)
        
        real_url, status, html, headers = await self.fetch(url)
        if status != 200 or not html: return
        
        real_url_str = str(real_url)

        # Discovery: Find links
        soup = BeautifulSoup(html, 'html.parser')
        
        # <a> links
        for a in soup.find_all('a', href=True):
            link = urljoin(real_url_str, str(a['href']))
            if urlparse(link).netloc == self.base_domain and link not in self.visited:
                queue.put_nowait(link)
        
        # <script src> links (JS Discovery)
        scripts = [urljoin(real_url_str, str(s.get('src'))) for s in soup.find_all('script') if s.get('src')]
        for s in scripts:
            if urlparse(s).netloc == self.base_domain and s not in self.js_files_scanned:
                asyncio.create_task(self.process_js(s, queue))

        # Run Plugins (Audit)
        await self.run_plugins(real_url_str, html, headers)

    async def process_js(self, js_url: str, queue: asyncio.Queue[str]) -> None:
        if js_url in self.js_files_scanned: return
        self.js_files_scanned.add(js_url)
        
        _, status, content, _ = await self.fetch(js_url)
        if status != 200 or not content: return
        
        # 1. Run JS-capable plugins (Secrets)
        for plugin in self.plugins:
            if hasattr(plugin, 'check_js'):
                 res = await plugin.check_js(self.session, js_url, html=content) # type: ignore
                 if res:
                    self.vulnerabilities.extend(res)
            elif plugin.name == "Secrets & Tokens": # Fallback for legacy
                res = await plugin.check(self.session, js_url, html=content)
                self.vulnerabilities.extend(res)

        # 2. Discovery: Find endpoints in JS
        found_paths = re.findall(REGEX_ENDPOINTS, content)
        for path in found_paths:
             if not path.endswith(('.png', '.jpg', '.svg', '.css', '.woff')):
                 full_url = urljoin(js_url, path)
                 if urlparse(full_url).netloc == self.base_domain and full_url not in self.visited:
                     try:
                         queue.put_nowait(full_url)
                     except Exception: pass

    async def run_plugins(self, url: str, html: str, headers: Dict[str, str]) -> None:
        parsed = urlparse(url)
        params: Dict[str, Any] = dict(parse_qsl(parsed.query))
        
        logger.debug(f"Running plugins for {url} with params {params}")
        
        tasks: List[asyncio.Task[List[Vulnerability]]] = []
        for plugin in self.plugins:
            tasks.append(asyncio.create_task(plugin.check(self.session, url, html, headers, params)))
        
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                for vuln in r:
                    logger.info(f"[!] Vulnerability found: {vuln.type} at {vuln.url}")
                self.vulnerabilities.extend(r)
        
        # Track endpoint
        self.endpoints_found.append({"url": url, "method": "GET", "params": list(params.keys())})
