#!/usr/bin/env python3
"""
WebVulnScanner (extendido)

Novedades añadidas:
 - Detección heurística de CSRF (formularios sin token aparente)
 - Detección heurística de Open Redirects (parámetros tipo redirect/next/url que reflejan URLs)
 - Detección heurística de SSRF (parámetros que aceptan URLs/hosts) - *no realiza explotar remoto*; solo marca posibles vectores
 - Heurística de RCE (búsqueda de endpoints de upload, parámetros que aceptan comandos) - *no ejecuta comandos*
 - Mejor documentación, setup.py mínimo y Dockerfile para ejecutar la herramienta en contenedor

Principios de seguridad:
 - TODO intrusivo (ej.: payloads time-based, SSRF trigger, ejecución remota) sólo si se pasa --allow-intrusive y --authorized.
 - Heurísticas no intrusivas se ejecutan por defecto y marcan posibles vectores para revisión humana.

Archivos incluidos en este documento:
 - webvulnscanner_ext.py  -> código principal
 - Dockerfile            -> contenedor para ejecutar la herramienta
 - setup.py              -> paquete mínimo para instalación con pip

Uso (ejemplo):
 python3 webvulnscanner_ext.py --url https://example.com --crawl --checks xss sqli csrf openredirect ssrf rce --report out.json

ADVERTENCIA: usar solo en entornos autorizados.
"""

# -------------------------
# Código: webvulnscanner_ext.py
# -------------------------

import argparse
import json
import os
import re
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl

import requests
from bs4 import BeautifulSoup

# ---------------------------------
# Utilidades y configuración
# ---------------------------------

DEFAULT_HEADERS = {"User-Agent": "WebVulnScanner-Ext/1.0 (+https://example.org)"}
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover=alert(1) x="']
SQL_ERRORS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
]
DEFAULT_WORDLIST = ['admin', 'login', 'dashboard', 'config.php', 'robots.txt', 'sitemap.xml', '.git', '.env', 'backup.zip']

# Campos comunes que suelen indicar URLs o redirecciones
URL_PARAM_NAMES = ['url', 'next', 'redirect', 'return', 'rurl', 'dest', 'destination']

# Campos que suelen indicar upload/file
UPLOAD_PARAM_NAMES = ['file', 'upload', 'image', 'avatar']

# ---------------------------------
# Helpers
# ---------------------------------

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def timestamp():
    from datetime import datetime

    return datetime.utcnow().isoformat() + 'Z'


def safe_request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    try:
        resp = session.request(method, url, timeout=15, headers=kwargs.pop('headers', DEFAULT_HEADERS), **kwargs)
        return resp
    except requests.RequestException as ex:
        eprint(f"[safe_request] {method} {url} -> {ex}")
        raise

# ---------------------------------
# Heurísticas añadidas
# ---------------------------------

def detect_csrf_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    """Busca formularios que no parezcan llevar tokens anti-CSRF en inputs ocultos o en campos llamados csrf/_token"""
    findings = []
    soup = BeautifulSoup(html, 'html.parser')
    for form in soup.find_all('form'):
        inputs = [i.get('name', '').lower() for i in form.find_all(['input','textarea','select']) if i.get('name')]
        has_csrf = any('csrf' in n or '_token' in n or 'csrf_token' in n for n in inputs)
        if not has_csrf:
            action = form.get('action') or base_url
            method = form.get('method') or 'GET'
            findings.append({'action': urljoin(base_url, action), 'method': method.upper(), 'inputs': inputs})
    return findings


def detect_open_redirect_forms_or_params(url: str, params: Dict[str, str], html: str) -> List[Dict[str, Any]]:
    """Heurística: si existen parámetros tipo 'next'/'redirect' que retornan la URL tal cual, marcar como posible open redirect."""
    findings = []
    # revisar params de query o forms
    for name, value in params.items():
        if name.lower() in URL_PARAM_NAMES:
            # marca si el valor es una URL absoluta (posible redirect) o si el valor es reflejado en la página
            parsed = urlparse(value)
            is_abs = bool(parsed.scheme and parsed.netloc)
            reflected = False
            try:
                if value and value in html:
                    reflected = True
            except Exception:
                reflected = False
            findings.append({'param': name, 'value': value, 'is_url': is_abs, 'reflected_in_page': reflected, 'endpoint': url})
    return findings


def detect_ssrf_candidates(params: Dict[str, str]) -> List[Dict[str, Any]]:
    """Marca parámetros que podrían permitir SSRF por aceptar URLs/hosts."""
    findings = []
    for name, value in params.items():
        if name.lower() in URL_PARAM_NAMES or 'callback' in name.lower() or 'host' in name.lower():
            findings.append({'param': name, 'value': value})
    return findings


def detect_rce_candidates(html: str, url: str) -> List[Dict[str, Any]]:
    """Detecta endpoints que podrían permitir RCE, por ejemplo upload o inputs con nombres sospechosos."""
    findings = []
    soup = BeautifulSoup(html, 'html.parser')
    for form in soup.find_all('form'):
        inputs = [i.get('name', '') for i in form.find_all(['input','textarea','select']) if i.get('name')]
        upload_like = any(any(u in n.lower() for u in UPLOAD_PARAM_NAMES) for n in inputs)
        # si se detecta upload, marcar
        if upload_like:
            action = form.get('action') or url
            findings.append({'action': urljoin(url, action), 'inputs': inputs})
    # además buscar endpoints con endpoints .php, .aspx que suelen permitir parámetros de comando en apps viejas
    if re.search(r'\b(cmd|execute|run)\b', html, re.IGNORECASE):
        findings.append({'note': 'posible referencia a ejecución de comandos en HTML', 'endpoint': url})
    return findings

# ---------------------------------
# Integración con crawler y checks existentes
# ---------------------------------

def extract_links(base_url: str, html: str) -> Set[str]:
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for tag in soup.find_all(['a', 'form', 'link', 'script']):
        if tag.name == 'a' and tag.get('href'):
            links.add(urljoin(base_url, tag['href']))
        if tag.name == 'form' and tag.get('action'):
            links.add(urljoin(base_url, tag['action']))
        if tag.name == 'link' and tag.get('href'):
            links.add(urljoin(base_url, tag['href']))
        if tag.name == 'script' and tag.get('src'):
            links.add(urljoin(base_url, tag['src']))
    return links


def _fetch_page(session: requests.Session, url: str) -> str:
    try:
        r = safe_request(session, 'GET', url)
        if 'text' in r.headers.get('Content-Type', ''):
            return r.text
        return ''
    except Exception:
        return ''


def crawl(start_url: str, session: requests.Session, max_pages: int = 200, workers: int = 10) -> Tuple[Set[str], Dict[str, str]]:
    parsed_root = urlparse(start_url)
    base_netloc = parsed_root.netloc

    to_visit = {start_url}
    visited: Set[str] = set()
    pages: Dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        while to_visit and len(visited) < max_pages:
            futures = {}
            batch = list(to_visit)[:workers]
            to_visit = set(list(to_visit)[workers:])
            for url in batch:
                if url in visited:
                    continue
                futures[ex.submit(_fetch_page, session, url)] = url

            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    html = fut.result()
                    if html is None:
                        visited.add(url)
                        continue
                    pages[url] = html
                    visited.add(url)
                    links = extract_links(url, html)
                    for l in links:
                        p = urlparse(l)
                        if p.netloc == base_netloc and l not in visited and len(visited) + len(to_visit) < max_pages:
                            to_visit.add(l)
                except Exception:
                    visited.add(url)
    return set(pages.keys()), pages

# ---------------------------------
# Checks básicos reutilizados (XSS, SQLi, dir brute)
# ---------------------------------

def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    res = {}
    res['hsts'] = 'strict-transport-security' in (k.lower() for k in headers.keys())
    res['csp'] = 'content-security-policy' in (k.lower() for k in headers.keys())
    res['x_frame_options'] = 'x-frame-options' in (k.lower() for k in headers.keys())
    res['x_content_type_options'] = 'x-content-type-options' in (k.lower() for k in headers.keys())
    res['referrer_policy'] = 'referrer-policy' in (k.lower() for k in headers.keys())
    return res


def detect_reflected_xss(url: str, session: requests.Session, params: Dict[str, str]) -> Dict[str, Any]:
    findings = []
    for name in params.keys():
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[name] = payload
            try:
                r = safe_request(session, 'GET', url, params=test_params)
                if payload in r.text:
                    findings.append({'param': name, 'payload': payload, 'url': r.url})
            except Exception:
                continue
    return {'reflected_xss': findings}


def detect_sqli_error_based(url: str, session: requests.Session, params: Dict[str, str]) -> Dict[str, Any]:
    findings = []
    for name in params.keys():
        test_params = params.copy()
        test_params[name] = params.get(name, '') + "'"
        try:
            r = safe_request(session, 'GET', url, params=test_params)
            lower = r.text.lower()
            for err in SQL_ERRORS:
                if err in lower:
                    findings.append({'param': name, 'evidence': err, 'url': r.url})
        except Exception:
            continue
    return {'sqli_error_based': findings}


def dir_bruteforce(base_url: str, session: requests.Session, wordlist: List[str], workers: int = 10) -> Dict[str, Any]:
    results = []
    parsed = urlparse(base_url)
    scheme_host = f"{parsed.scheme}://{parsed.netloc}"

    def _check(path):
        url = urljoin(scheme_host, path)
        try:
            r = safe_request(session, 'GET', url)
            if r.status_code in (200, 301, 302, 401):
                return {'path': path, 'status': r.status_code, 'url': url}
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check, w): w for w in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    return {'dir_bruteforce': results}

# ---------------------------------
# Orquestador principal extendido
# ---------------------------------

def run_checks(target: str, opts) -> Dict[str, Any]:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    report: Dict[str, Any] = {'meta': {}, 'recon': {}, 'crawl': {}, 'checks': {}, 'timestamp': timestamp()}
    report['meta']['target'] = target
    report['meta']['options'] = vars(opts)

    base = target if target.startswith('http') else 'https://' + target

    # Reconocimiento pasivo
    try:
        r = safe_request(session, 'GET', base)
        headers = dict(r.headers)
        root_html = r.text if 'text' in r.headers.get('Content-Type','') else ''
    except Exception as ex:
        headers = {}
        root_html = ''
    report['recon']['headers'] = headers
    report['recon']['security_headers'] = check_security_headers(headers)

    # Crawling
    pages = {}
    if opts.crawl:
        urls, pages = crawl(base, session, max_pages=opts.max_pages, workers=opts.workers)
        report['crawl']['pages_count'] = len(urls)
        report['crawl']['pages'] = list(urls)[:200]
    else:
        pages[base] = root_html
        report['crawl']['pages_count'] = 1
        report['crawl']['pages'] = [base]

    # Extraer endpoints y aplicar diversas heurísticas
    endpoints = []
    for url, html in pages.items():
        parsed = urlparse(url)
        q = dict(parse_qsl(parsed.query))
        if q:
            endpoints.append((url, q, html))
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action') or url
            action = urljoin(url, action)
            inputs = {}
            for inp in form.find_all(['input','textarea','select']):
                name = inp.get('name')
                if not name:
                    continue
                inputs[name] = inp.get('value') or 'test'
            endpoints.append((action, inputs, str(form)))

    report['crawl']['endpoints_count'] = len(endpoints)

    checks = {'xss': [], 'sqli_error': [], 'sqli_time': [], 'csrf': [], 'openredirect': [], 'ssrf_candidates': [], 'rce_candidates': []}

    for url, params, html in endpoints:
        # XSS
        if 'xss' in opts.checks:
            try:
                res = detect_reflected_xss(url, session, params)
                if res.get('reflected_xss'):
                    checks['xss'].append({'url': url, 'findings': res['reflected_xss']})
            except Exception:
                pass
        # SQLi
        if 'sqli' in opts.checks:
            try:
                res = detect_sqli_error_based(url, session, params)
                if res.get('sqli_error_based'):
                    checks['sqli_error'].append({'url': url, 'findings': res['sqli_error_based']})
            except Exception:
                pass
            if opts.allow_intrusive and opts.authorized and 'sqli' in opts.checks:
                # time-based (intrusivo)
                try:
                    res = detect_sqli_time_based(url, session, params)
                    if res.get('sqli_time_based'):
                        checks['sqli_time'].append({'url': url, 'findings': res['sqli_time_based']})
                except Exception:
                    pass
        # CSRF
        if 'csrf' in opts.checks:
            try:
                cs = detect_csrf_forms(html, url)
                if cs:
                    checks['csrf'].append({'url': url, 'forms': cs})
            except Exception:
                pass
        # Open Redirect
        if 'openredirect' in opts.checks:
            try:
                orr = detect_open_redirect_forms_or_params(url, params, html)
                if orr:
                    checks['openredirect'].append({'url': url, 'findings': orr})
            except Exception:
                pass
        # SSRF candidates
        if 'ssrf' in opts.checks:
            try:
                s = detect_ssrf_candidates(params)
                if s:
                    checks['ssrf_candidates'].append({'url': url, 'candidates': s})
            except Exception:
                pass
        # RCE candidates
        if 'rce' in opts.checks:
            try:
                rce = detect_rce_candidates(html, url)
                if rce:
                    checks['rce_candidates'].append({'url': url, 'findings': rce})
            except Exception:
                pass

    report['checks'] = checks

    # Directorios
    if opts.dir_bruteforce:
        wl = DEFAULT_WORDLIST
        if opts.wordlist:
            try:
                with open(opts.wordlist, 'r', encoding='utf-8') as f:
                    wl = [l.strip() for l in f if l.strip()]
            except Exception:
                pass
        report['checks'].update(dir_bruteforce(base, session, wl, workers=opts.workers))

    # Integración sqlmap (intrusivo)
    if opts.use_sqlmap:
        if not shutil.which('sqlmap'):
            report.setdefault('tools', {})['sqlmap'] = {'error': 'sqlmap no encontrado en PATH'}
        else:
            if opts.allow_intrusive and opts.authorized:
                sql_results = []
                for url, params, html in endpoints:
                    if params:
                        try:
                            res = sqlmap_run(url, opts.sqlmap_options or [])
                            sql_results.append({'url': url, 'result': res})
                        except Exception as ex:
                            sql_results.append({'url': url, 'error': str(ex)})
                report.setdefault('tools', {})['sqlmap'] = sql_results
            else:
                report.setdefault('tools', {})['sqlmap'] = {'skipped': 'require --allow-intrusive and --authorized'}

    report['meta']['finished_at'] = timestamp()
    return report

# Reutilizamos funciones de SQL time based y sqlmap_run del anterior archivo

def detect_sqli_time_based(url: str, session: requests.Session, params: Dict[str, str]) -> Dict[str, Any]:
    findings = []
    payloads = ["' OR SLEEP(5)-- ", "' OR pg_sleep(5)-- "]
    for name in params.keys():
        for payload in payloads:
            test_params = params.copy()
            test_params[name] = payload
            try:
                start = time.time()
                r = safe_request(session, 'GET', url, params=test_params)
                elapsed = time.time() - start
                if elapsed > 4.0:
                    findings.append({'param': name, 'payload': payload, 'elapsed': elapsed, 'url': r.url})
            except Exception:
                continue
    return {'sqli_time_based': findings}


def sqlmap_run(target_url: str, options: List[str]) -> Dict[str, Any]:
    sqlmap_bin = shutil.which('sqlmap')
    if not sqlmap_bin:
        return {'error': 'sqlmap no encontrado en PATH'}
    cmd = [sqlmap_bin, '-u', target_url] + options + ['--batch']
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return {'returncode': p.returncode, 'stdout': p.stdout[:5000], 'stderr': p.stderr[:1000]}
    except Exception as ex:
        return {'error': str(ex)}

# ---------------------------------
# CLI builder
# ---------------------------------

def build_parser():
    p = argparse.ArgumentParser(description='WebVulnScanner - Evaluación web extendida (CSRF, SSRF, Open Redirect, RCE)')
    p.add_argument('--url', '--target', dest='url', required=True, help='URL objetivo (p. ej. https://example.com)')
    p.add_argument('--crawl', action='store_true', help='Realizar crawling del sitio')
    p.add_argument('--max-pages', type=int, default=200, help='Máximo de páginas a rastrear durante el crawling')
    p.add_argument('--workers', type=int, default=10, help='Hilos para crawling y bruteforce')
    p.add_argument('--checks', nargs='+', default=['xss', 'sqli', 'csrf', 'openredirect', 'ssrf', 'rce'], help='Checks a ejecutar: xss sqli csrf openredirect ssrf rce')
    p.add_argument('--dir-bruteforce', action='store_true', dest='dir_bruteforce', help='Habilitar búsqueda de directorios comunes')
    p.add_argument('--wordlist', help='Ruta a wordlist para bruteforce de directorios')
    p.add_argument('--use-sqlmap', action='store_true', help='Integrar y ejecutar sqlmap (intrusivo)')
    p.add_argument('--sqlmap-options', nargs='*', help='Opciones para sqlmap (ej: --level 3 --risk 1)')
    p.add_argument('--allow-intrusive', action='store_true', help='Permitir pruebas intrusivas (REQUIERE --authorized)')
    p.add_argument('--authorized', action='store_true', help='Confirmo que tengo autorización para testear el objetivo')
    p.add_argument('--report', default='webvuln_report_ext.json', help='Archivo JSON de salida')
    return p


def main_cli():
    parser = build_parser()
    args = parser.parse_args()
    if args.allow_intrusive and not args.authorized:
        eprint('ERROR: --allow-intrusive requiere --authorized. Abortando.')
        sys.exit(2)
    report = run_checks(args.url, args)
    try:
        with open(args.report, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] Reporte guardado en {args.report}")
    except Exception as ex:
        eprint(f"No se pudo guardar el reporte: {ex}")


if __name__ == '__main__':
    main_cli()

# ---------------------------------
# Dockerfile
# ---------------------------------
DOCKERFILE = r"""
# Dockerfile para WebVulnScanner-Ext
FROM python:3.11-slim
WORKDIR /app
COPY webvulnscanner_ext.py /app/webvulnscanner_ext.py
RUN pip install --no-cache-dir requests beautifulsoup4
ENTRYPOINT ["python3","/app/webvulnscanner_ext.py"]
"""

# ---------------------------------
# setup.py (mínimo)
# ---------------------------------
SETUP_PY = r"""
from setuptools import setup

setup(
    name='webvulnscanner_ext',
    version='0.1.0',
    py_modules=['webvulnscanner_ext'],
    install_requires=['requests', 'beautifulsoup4'],
    entry_points={'console_scripts': ['webvulnscanner-ext = webvulnscanner_ext:main_cli']},
)
"""

# Guardar Dockerfile y setup.py para que el usuario las copie si lo desea
print('\n--- Archivo Dockerfile (contenido guardado en la variable DOCKERFILE) ---\n')
print(DOCKERFILE)
print('\n--- Archivo setup.py (contenido guardado en la variable SETUP_PY) ---\n')
print(SETUP_PY)
