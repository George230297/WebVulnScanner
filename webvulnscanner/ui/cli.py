import argparse
import asyncio
import json
import sys
from collections import defaultdict
from webvulnscanner.config import ScanConfig
from webvulnscanner.core.engine import AsyncScanner
from webvulnscanner.reporting.formatter import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="WebVulnScanner v2 (Modular)")
    parser.add_argument('--url', required=True, help="Target URL")
    parser.add_argument('--checks', nargs='+', default=[], help="Specific checks to run (default: all)")
    parser.add_argument('--max-pages', type=int, default=50)
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument('--report', default='report.json')
    args = parser.parse_args()
    
    print(f"[*] Iniciando escaneo asíncrono a {args.url}")
    
    config = ScanConfig(
        start_url=args.url if args.url.startswith('http') else f'https://{args.url}',
        max_pages=args.max_pages,
        concurrency=args.workers,
        checks=args.checks
    )
    
    scanner = AsyncScanner(config)
    
    async def run():
        async with scanner:
            await scanner.crawl_loop()
            
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por usuario.")
    except Exception as e:
        print(f"[!] Error: {e}")
        
    # Process results
    results = prepare_results(args.url, scanner)
    
    # Save JSON
    with open(args.report, 'w') as f:
        f.write(ReportGenerator.generate_json(results))
        
    # Save Markdown
    md_file = args.report.replace('.json', '.md') if args.report.endswith('.json') else args.report + '.md'
    with open(md_file, 'w') as f:
        f.write(ReportGenerator.generate_markdown(results))
        
    print(f"[+] Escaneo terminado. {len(scanner.visited)} páginas escaneadas.")
    print(f"[+] Reportes guardados: {args.report}, {md_file}")

def prepare_results(target, scanner):
    checks_data = defaultdict(list)
    for v in scanner.vulnerabilities:
        # Categorize
        if 'XSS' in v.type: key = 'xss'
        elif 'SQL' in v.type: key = 'sqli'
        elif 'Secret' in v.type: key = 'secrets'
        elif 'CSRF' in v.type: key = 'csrf'
        elif 'Header' in v.type: key = 'headers'
        else: key = 'general'
        
        checks_data[key].append({
            'type': v.type,
            'url': v.url,
            'param': v.param,
            'evidence': v.evidence
        })
        
    return {
        'meta': {'target': target, 'scanner': 'v2_modular'},
        'crawl': {
            'pages_count': len(scanner.visited),
            'js_files_scanned': list(scanner.js_files_scanned)
        },
        'checks': dict(checks_data)
    }

if __name__ == "__main__":
    main()
