import asyncio
import aiohttp
import re
import logging
import json
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl
from typing import Set, List, Dict, Optional, Any

from webvulnscanner.config import ScanConfig, DEFAULT_HEADERS, SENSITIVE_FILES, REGEX_ENDPOINTS
from webvulnscanner.models.vulnerability import Vulnerability
from webvulnscanner.plugins import ALL_PLUGINS

logger = logging.getLogger("WebVulnScanner")

class AsyncScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.visited: Set[str] = set()
        self.js_files_scanned: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints_found: List[Dict[str, Any]] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.base_domain = urlparse(config.start_url).netloc
        
        # Initialize plugins
        self.plugins = [Plugin() for Plugin in ALL_PLUGINS]
        
        # Configure SSL context based on authorization/requirements
        self.ssl_context = ssl.create_default_context()
        if not self.config.authorized: # Assuming 'authorized' implies strict checking or specific certs
             # If authorized is False, we might default to strict, or if user asked for insecure?
             # For now, let's assume standard behavior is strictly verify, unless we want to allow self-signed for testing.
             # Standard "clean code" would default to verifying.
             pass
        else:
             # Example: if user explicitly allowed insecure in config (missing field currently), we'd do check_hostname=False
             # self.ssl_context.check_hostname = False
             # self.ssl_context.verify_mode = ssl.CERT_NONE
             pass

    async def __aenter__(self) -> "AsyncScanner":
        timeout = aiohttp.ClientTimeout(total=20)
        # Create a TCPConnector with the configured SSL context
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        self.session = aiohttp.ClientSession(
            headers=DEFAULT_HEADERS, 
            timeout=timeout,
            connector=connector
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.session:
            await self.session.close()

    async def fetch(self, url: str, method: str = "GET", params: Optional[Dict] = None, data: Any = None) -> tuple[str, int, str, Any]:
        async with self.semaphore:
            try:
                if not self.session:
                    raise RuntimeError("Session not initialized")
                    
                async with self.session.request(method, url, params=params, data=data, allow_redirects=True) as resp:
                    # Explicitly handle encoding to avoid errors='ignore' hiding issues entirely, 
                    # but fallback gracefully if needed.
                    try:
                        text = await resp.text()
                    except UnicodeDecodeError:
                        text = await resp.text(errors='replace')
                        
                    return str(resp.url), resp.status, text, resp.headers
            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
                return url, 0, "", {}

    async def crawl_loop(self) -> None:
        queue: asyncio.Queue[str] = asyncio.Queue()
        queue.put_nowait(self.config.start_url)
        
        # 1. WAF Check (Blocking, important to know early)
        await self.check_waf()
        
        # 2. Sensitive Files (Start in background)
        # We track this task to ensure it completes before finishing if critical, 
        # or let it run parallel. For scanning, usually parallel is fine.
        asyncio.create_task(self.check_sensitive_files())

        # 3. Main Loop
        while not queue.empty() and len(self.visited) < self.config.max_pages:
            tasks = []
            # Batch processing based on concurrency and queue size
            count = min(queue.qsize(), self.config.concurrency)
            for _ in range(count):
                url = await queue.get()
                if url not in self.visited:
                    tasks.append(self.process_url(url, queue))
            
            if tasks:
                await asyncio.gather(*tasks)

    async def check_waf(self) -> None:
        logger.info("[*] Comprobando WAF...")
        try:
             # Simple heuristic: send a harmless payload to see if blocked
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

    async def process_url(self, url: str, queue: asyncio.Queue) -> None:
        if url in self.visited: return
        self.visited.add(url)
        
        real_url, status, html, headers = await self.fetch(url)
        if status != 200 or not html: return
        
        real_url_str = str(real_url)

        # Discovery: Find links
        soup = BeautifulSoup(html, 'html.parser')
        
        # <a> links
        for a in soup.find_all('a', href=True):
            link = urljoin(real_url_str, a['href'])
            # Ensure strict domain scope
            if urlparse(link).netloc == self.base_domain and link not in self.visited:
                queue.put_nowait(link)
        
        # <script src> links (JS Discovery)
        scripts = [urljoin(real_url_str, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        for s in scripts:
            if urlparse(s).netloc == self.base_domain and s not in self.js_files_scanned:
                # Add a task to analyze JS
                asyncio.create_task(self.process_js(s, queue))

        # Run Plugins (Audit)
        await self.run_plugins(real_url_str, html, headers)

    async def process_js(self, js_url: str, queue: asyncio.Queue) -> None:
        if js_url in self.js_files_scanned: return
        self.js_files_scanned.add(js_url)
        
        _, status, content, _ = await self.fetch(js_url)
        if status != 200 or not content: return
        
        # 1. Run JS-capable plugins (Secrets)
        for plugin in self.plugins:
            # Explicitly checking plugin capability or name is better than hardcoding
            # Logic: If plugin handles JS analysis.
            if plugin.name == "Secrets & Tokens":
                # Assuming plugin.check signature is flexible or we adapt it
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

    async def run_plugins(self, url: str, html: str, headers: Any) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        
        tasks = []
        for plugin in self.plugins:
            # Future improvement: Plugin.should_run(context)
            tasks.append(plugin.check(self.session, url, html, headers, params))
        
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                self.vulnerabilities.extend(r)
        
        # Track endpoint
        self.endpoints_found.append({"url": url, "method": "GET", "params": list(params.keys())})
