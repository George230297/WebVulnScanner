import argparse
import asyncio
from webvulnscanner.config import ScanConfig
from webvulnscanner.core.engine import AsyncScanner
from webvulnscanner.reporting.formatter import ReportGenerator

def main() -> None:
    parser = argparse.ArgumentParser(description="WebVulnScanner v2 (Modular)")
    parser.add_argument('--url', required=True, help="Target URL")
    parser.add_argument('--checks', nargs='+', default=[], help="Specific checks to run (default: all)")
    parser.add_argument('--max-pages', type=int, default=50, help='Número máximo de páginas a visitar durante el crawling')
    parser.add_argument('--workers', type=int, default=20, help='Número de hilos/conexiones concurrentes')
    parser.add_argument('--report', default='report.json', help='Nombre y ruta del archivo de reporte a generar')
    parser.add_argument('--auth-jwt', help='Token JWT estático puro para escaneo con estado (Stateful Scanning)')
    parser.add_argument('--auth-cookie', help='Volcado en crudo del encabezado Cookie para inicio de sesión pasivo')
    args = parser.parse_args()
    
    print(f"[*] Iniciando escaneo asíncrono a {args.url}")
    if args.auth_jwt or args.auth_cookie:
        print(f"[*] Modo Autenticado Activado (Stateful Scanning)")
    
    config = ScanConfig(
        start_url=args.url if args.url.startswith('http') else f'https://{args.url}',
        max_pages=args.max_pages,
        concurrency=args.workers,
        checks=args.checks,
        auth_jwt=args.auth_jwt,
        auth_cookie=args.auth_cookie
    )
    
    scanner = AsyncScanner(config)
    
    async def run() -> None:
        async with scanner:
            await scanner.crawl_loop()
            
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por usuario.")
    except Exception as e:
        print(f"[!] Error inesperado en el escáner: {e}")
        
    # Process results via the centralized formatter
    results = ReportGenerator.prepare_results(args.url, scanner)
    
    # Save JSON
    with open(args.report, 'w', encoding='utf-8') as f:
        f.write(ReportGenerator.generate_json(results))
        
    # Save Markdown
    md_file = args.report.replace('.json', '.md') if args.report.endswith('.json') else args.report + '.md'
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(ReportGenerator.generate_markdown(results))
        
    print(f"[+] Escaneo terminado. {len(scanner.visited)} páginas escaneadas.")
    print(f"[+] Reportes guardados: {args.report}, {md_file}")

if __name__ == "__main__":
    main()
