#!/usr/bin/env python3
"""
WebVulnScanner v2 (Core Asíncrono)

Novedades:
 - Motor basado en asyncio/aiohttp (No-bloqueante).
 - Análisis estático de archivos JavaScript (Endpoints ocultos y Secretos).
 - Detección básica de WAF.
 - Sistema de reportes compatible con la TUI existente.
"""

import argparse
import asyncio
import aiohttp
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qsl
from bs4 import BeautifulSoup

# Configuración básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WebVulnScanner")

# --- Constantes y Regex ---
DEFAULT_HEADERS = {"User-Agent": "WebVulnScanner/2.0 (Async)"}
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover=alert(1) x="']
SQL_ERRORS = [
    'you have an error in your sql syntax', 'warning: mysql',
    'unclosed quotation mark', 'quoted string not properly terminated'
]

# Regex para encontrar secretos en JS
REGEX_SECRETS = {
    'AWS API Key': r'AKIA[0-9A-Z]{16}',
    'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
    'Generic Token': r'(api_key|auth_token|access_token)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})[\"\']'
}

# Regex para encontrar endpoints relativos en JS (ej: "/api/v1/users")
REGEX_ENDPOINTS = r'["\'](\/[a-zA-Z0-9_./-]+)["\']'

# Lista de archivos sensibles comunes para búsqueda rápida
SENSITIVE_FILES = [
    '.env', '.git/HEAD', '.svn/entries', '.DS_Store',
    'wp-config.php.bak', 'config.php.bak', 'backup.zip', 'database.sql',
    'package-lock.json', 'composer.lock'
]

# Headers de seguridad recomendados para verificar
SECURITY_HEADERS = {
    'Content-Security-Policy': 'Missing CSP',
    'X-Frame-Options': 'Missing X-Frame-Options (Clickjacking Risk)',
    'Strict-Transport-Security': 'Missing HSTS',
    'X-Content-Type-Options': 'Missing X-Content-Type-Options'
}

@dataclass
class Vulnerability:
    type: str
    url: str
    param: Optional[str] = None
    evidence: Optional[str] = None
    severity: str = "Medium"

@dataclass
class ScanConfig:
    start_url: str
    max_pages: int = 100
    concurrency: int = 20
    checks: List[str] = field(default_factory=list)
    allow_intrusive: bool = False
    authorized: bool = False
    dir_bruteforce: bool = False
    wordlist: Optional[str] = None

class AsyncScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.visited: Set[str] = set()
        self.js_files_scanned: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints_found: List[Dict] = [] # Para el reporte
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.base_domain = urlparse(config.start_url).netloc
        self.headers_checked = False

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=15)
        self.session = aiohttp.ClientSession(headers=DEFAULT_HEADERS, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch(self, url: str, method="GET", params=None, data=None):
        async with self.semaphore:
            try:
                async with self.session.request(method, url, params=params, data=data, allow_redirects=True) as resp:
                    text = await resp.text(errors='ignore')
                    return resp.url, resp.status, text, resp.headers
            except Exception:
                return url, 0, "", {}

    async def analyze_js_static(self, js_url: str, queue: asyncio.Queue):
        """Descarga y analiza archivos JS en busca de secretos y rutas ocultas."""
        if js_url in self.js_files_scanned:
            return
        self.js_files_scanned.add(js_url)
        
        _, status, content, _ = await self.fetch(js_url)
        if status != 200 or not content:
            return

        # 1. Buscar Secretos
        for name, regex in REGEX_SECRETS.items():
            matches = re.findall(regex, content)
            for m in matches:
                evidence = m[0] if isinstance(m, tuple) else m
                self.vulnerabilities.append(
                    Vulnerability("JS Secret Leak", js_url, None, f"{name}: {evidence[:15]}...", "High")
                )

        # 2. Buscar Endpoints Ocultos (Discovery)
        found_paths = re.findall(REGEX_ENDPOINTS, content)
        for path in found_paths:
            # Filtrar rutas de archivos estáticos comunes
            if not path.endswith(('.png', '.jpg', '.svg', '.css', '.woff')):
                full_url = urljoin(str(js_url), path)
                # Si es del mismo dominio y no visitada, añadir a cola
                if urlparse(full_url).netloc == self.base_domain and full_url not in self.visited:
                    # Añadir a la cola de escaneo principal
                    queue.put_nowait(full_url)

    async def audit_page(self, url: str, html: str):
        """Audita una página HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        # 1. Detectar JS y encolar análisis estático
        scripts = [urljoin(url, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        # Nota: El análisis JS se lanza como tarea de fondo en el bucle principal o aquí
        # Para simplificar, devolvemos los scripts para que el loop principal los gestione si es necesario,
        # pero idealmente los analizamos aquí mismo.
        js_tasks = [self.analyze_js_static_wrapper(s) for s in scripts if urlparse(s).netloc == self.base_domain]
        if js_tasks:
            await asyncio.gather(*js_tasks)

        # 2. Checks heurísticos (XSS/SQLi/CSRF)
        tasks = []
        
        # CSRF Heurístico
        if 'csrf' in self.config.checks:
            forms = soup.find_all('form')
            for form in forms:
                if not any('csrf' in i.get('name', '').lower() for i in form.find_all('input')):
                    action = form.get('action') or ""
                    self.vulnerabilities.append(Vulnerability("Potential CSRF", urljoin(url, action), None, "Form without CSRF token", "Low"))

        # SSRF / RCE Candidates
        if 'ssrf' in self.config.checks and params:
            for k, v in params.items():
                if k.lower() in ['url', 'redirect', 'next', 'uri']:
                    self.vulnerabilities.append(Vulnerability("SSRF Candidate", url, k, "Param accepts URLs", "Medium"))

        # XSS / SQLi (Requiere peticiones activas)
        if params:
            if 'xss' in self.config.checks:
                tasks.append(self.check_xss(url, params))
            if 'sqli' in self.config.checks:
                tasks.append(self.check_sqli(url, params))

        if tasks:
            await asyncio.gather(*tasks)
            
        # Guardar endpoint para reporte
        self.endpoints_found.append({"url": url, "method": "GET", "params": list(params.keys())})

    async def check_security_headers(self, url: str, headers: dict):
        """Verifica la presencia de headers de seguridad importantes."""
        if self.headers_checked: return
        self.headers_checked = True 
        
        for header, msg in SECURITY_HEADERS.items():
            # Buscar header case-insensitive
            if not any(h.lower() == header.lower() for h in headers.keys()):
                self.vulnerabilities.append(Vulnerability("Missing Security Header", self.base_domain, header, msg, "Low"))

    async def check_sensitive_files(self):
        """Intenta descubrir archivos sensibles en la raíz del dominio."""
        base_url = f"{urlparse(self.config.start_url).scheme}://{self.base_domain}"
        
        async def check_file(filename):
            target = urljoin(base_url + '/', filename)
            _, status, _, _ = await self.fetch(target)
            if status == 200:
                self.vulnerabilities.append(Vulnerability("Sensitive File Found", target, None, f"Exposed {filename}", "High"))

        # Lanzar peticiones concurrentes
        await asyncio.gather(*[check_file(f) for f in SENSITIVE_FILES])

    async def analyze_js_static_wrapper(self, url):
        # Wrapper simple porque analyze_js_static necesita la cola, 
        # pero aquí solo hacemos análisis pasivo de secretos para no complicar la recursión infinita
        if url in self.js_files_scanned: return
        self.js_files_scanned.add(url)
        _, st, content, _ = await self.fetch(url)
        if st == 200:
            for name, regex in REGEX_SECRETS.items():
                if re.search(regex, content):
                     self.vulnerabilities.append(Vulnerability("JS Secret Leak", url, None, name, "High"))

    async def check_xss(self, url: str, params: Dict[str, str]):
        for k in params:
            for p in XSS_PAYLOADS:
                p_mod = params.copy()
                p_mod[k] = p
                _, _, txt, _ = await self.fetch(url, params=p_mod)
                if p in txt:
                    self.vulnerabilities.append(Vulnerability("Reflected XSS", url, k, p, "High"))
                    return 

    async def check_sqli(self, url: str, params: Dict[str, str]):
        for k in params:
            p_mod = params.copy()
            p_mod[k] = "1'"
            _, _, txt, _ = await self.fetch(url, params=p_mod)
            if any(err in txt.lower() for err in SQL_ERRORS):
                self.vulnerabilities.append(Vulnerability("SQLi Error-Based", url, k, "DB Error triggered", "Critical"))
                return

    async def crawl_loop(self):
        queue = asyncio.Queue()
        queue.put_nowait(self.config.start_url)
        
        # WAF Check
        print("[*] Comprobando WAF...")
        _, status, _, _ = await self.fetch(self.config.start_url, params={'q': '<script>alert(1)</script>'})
        if status == 403:
            print("[!] ADVERTENCIA: Posible WAF detectado (403 Forbidden ante payload). Resultados pueden variar.")

        # Static Analysis Jobs (Run once)
        tasks_init = []
        tasks_init.append(self.check_sensitive_files())
        await asyncio.gather(*tasks_init)

        while not queue.empty() and len(self.visited) < self.config.max_pages:
            tasks = []
            # Sacar lote de URLs
            for _ in range(min(queue.qsize(), self.config.concurrency)):
                url = await queue.get()
                if url not in self.visited:
                    tasks.append(self.process_url(url, queue))
            
            if tasks:
                await asyncio.gather(*tasks)

    async def process_url(self, url, queue):
        if url in self.visited: return
        self.visited.add(url)
        
        real_url, status, html, headers = await self.fetch(url)
        if status != 200 or not html: return

        # Chequear headers (solo la primera vez o si cambia contexto, aquí lo hacemos once)
        await self.check_security_headers(str(real_url), headers)

        # Extracción de links
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            link = urljoin(str(real_url), a['href'])
            if urlparse(link).netloc == self.base_domain and link not in self.visited:
                queue.put_nowait(link)

        await self.audit_page(str(real_url), html)

# --- Bridge para compatibilidad con TUI y CLI ---

def run_checks(target: str, opts) -> Dict[str, Any]:
    """
    Función síncrona que envuelve el motor asíncrono.
    Mantiene la firma exacta que espera la TUI.
    """
    # Mapear opciones de TUI/CLI a ScanConfig
    checks = getattr(opts, 'checks', [])
    # Si viene de TUI, opts es un objeto simple, si viene de argparse es Namespace
    cfg = ScanConfig(
        start_url=target if target.startswith('http') else f'https://{target}',
        max_pages=getattr(opts, 'max_pages', 100),
        concurrency=getattr(opts, 'workers', 20),
        checks=checks,
        allow_intrusive=getattr(opts, 'allow_intrusive', False),
        authorized=getattr(opts, 'authorized', False)
    )

    # Ejecutar bucle asíncrono
    scanner = AsyncScanner(cfg)
    
    async def _run():
        async with scanner:
            await scanner.crawl_loop()
            
    try:
        # En entornos con loop existente (jupyter) esto falla, pero en CLI/TUI estándar funciona
        asyncio.run(_run())
    except Exception as e:
        # Fallback para debug
        print(f"Error en loop async: {e}")

    # Construir reporte compatible con formato antiguo
    report = {
        'meta': {'target': target, 'scanner': 'v2_async'},
        'recon': {'headers': {}},
        'crawl': {
            'pages_count': len(scanner.visited),
            'pages': list(scanner.visited)[:50],
            'js_files_scanned': list(scanner.js_files_scanned)
        },
        'checks': {
            'xss': [], 'sqli': [], 'csrf': [], 'secrets': [], 'general': []
        }
    }

    # Mapear vulnerabilidades al formato dict antiguo
    for v in scanner.vulnerabilities:
        item = {'url': v.url, 'evidence': v.evidence, 'param': v.param}
        if 'XSS' in v.type: report['checks']['xss'].append(item)
        elif 'SQLi' in v.type: report['checks']['sqli'].append(item)
        elif 'CSRF' in v.type: report['checks']['csrf'].append(item)
        elif 'Secret' in v.type: report['checks']['secrets'].append(item)
        else: report['checks']['general'].append({'type': v.type, **item})

    return report

# --- CLI Main ---
def main_cli():
    parser = argparse.ArgumentParser(description="WebVulnScanner v2 (Async)")
    parser.add_argument('--url', required=True)
    parser.add_argument('--checks', nargs='+', default=['xss','sqli','csrf','secrets'])
    parser.add_argument('--max-pages', type=int, default=50)
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument('--report', default='report.json')
    args = parser.parse_args()
    
    print(f"[*] Iniciando escaneo asíncrono a {args.url}")
    rep = run_checks(args.url, args)
    
    # Generate JSON
    with open(args.report, 'w') as f:
        json.dump(rep, f, indent=2)
    
    # Generate Markdown
    md_report = generate_markdown_report(rep)
    md_filename = args.report.replace('.json', '.md')
    if md_filename == args.report: md_filename += '.md' # Fallback
    
    with open(md_filename, 'w') as f:
        f.write(md_report)

    print(f"[+] Escaneo terminado. {len(rep['crawl']['pages'])} páginas.")
    print(f"[+] Reportes guardados: {args.report}, {md_filename}")

def generate_markdown_report(data: dict) -> str:
    """Genera un reporte legible en Markdown."""
    lines = []
    lines.append(f"# Reporte de Vulnerabilidades: {data['meta']['target']}")
    lines.append(f"**Scanner**: {data['meta']['scanner']}\n")
    
    # Resumen de Crawl
    lines.append("## Resumen de Reconocimiento")
    crawl = data['crawl']
    lines.append(f"- **Páginas Escaneadas**: {crawl['pages_count']}")
    lines.append(f"- **Archivos JS Analizados**: {len(crawl['js_files_scanned'])}")
    
    # Vulnerabilidades
    lines.append("\n## Hallazgos de Seguridad")
    
    checks = data['checks']
    total_vulns = 0
    
    # Mapeo de categorías
    categories = {
        'secrets': 'Secretos Filtrados (Critical/High)',
        'sqli': 'Inyecciones SQL (Critical)',
        'xss': 'Cross-Site Scripting (High)',
        'csrf': 'Problemas CSRF (Low)',
        'general': 'Otros Hallazgos (Headers, Files)'
    }
    
    for key, title in categories.items():
        items = checks.get(key, [])
        if not items: continue
        
        lines.append(f"\n### {title}")
        total_vulns += len(items)
        
        for idx, item in enumerate(items, 1):
            url = item.get('url', 'N/A')
            evidence = item.get('evidence', 'N/A')
            param = item.get('param')
            vuln_type = item.get('type', key.upper())
            
            lines.append(f"**{idx}. {vuln_type}**")
            lines.append(f"- **URL**: `{url}`")
            if param: lines.append(f"- **Parámetro Afectado**: `{param}`")
            lines.append(f"- **Evidencia**: `{evidence}`")
            lines.append("")

    if total_vulns == 0:
        lines.append("\n> [!NOTE]\n> No se encontraron vulnerabilidades obvias durante el escaneo.")

    return "\n".join(lines)

if __name__ == "__main__":
    main_cli()