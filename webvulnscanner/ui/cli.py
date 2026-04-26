import argparse
import asyncio
from webvulnscanner.config import ScanConfig
from webvulnscanner.core.engine import AsyncScanner
from webvulnscanner.core.network_engine import AsyncNetworkScanner
from webvulnscanner.reporting.formatter import ReportGenerator

def main() -> None:
    parser = argparse.ArgumentParser(description="WebVulnScanner v2 (Modular)")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--url', help="Target URL")
    target_group.add_argument('--ip', help="Target IP address para escaneo de infraestructura")
    parser.add_argument('--ports', help="Comma-separated list of ports to scan (e.g. 21,22,80,443)")
    parser.add_argument('--checks', nargs='+', default=[], help="Specific checks to run (default: all)")
    parser.add_argument('--max-pages', type=int, default=50, help='Número máximo de páginas a visitar durante el crawling')
    parser.add_argument('--workers', type=int, default=20, help='Número de hilos/conexiones concurrentes')
    parser.add_argument('--report', default='report.json', help='Nombre y ruta del archivo de reporte a generar')
    parser.add_argument('--auth-jwt', help='Token JWT estático puro para escaneo con estado (Stateful Scanning)')
    parser.add_argument('--auth-cookie', help='Volcado en crudo del encabezado Cookie para inicio de sesión pasivo')
    parser.add_argument('--evasion', type=int, choices=[0, 1, 2], default=0, help='Nivel de evasión WAF (0: Desactivado, 1: Ofuscación y Mutación de Payloads, 2: Fragmentación HTTP Avanzada + Ofuscación)')
    args = parser.parse_args()
    
    ports_list = list(range(1, 1025))
    if args.ports:
        ports_list = [int(p.strip()) for p in args.ports.split(',')]

    target_str = args.ip if args.ip else args.url

    if args.ip:
        print(f"[*] Iniciando escaneo asíncrono de red a {args.ip}")
    else:
        print(f"[*] Iniciando escaneo asíncrono web a {args.url}")
        
    if args.auth_jwt or args.auth_cookie:
        print(f"[*] Modo Autenticado Activado (Stateful Scanning)")
    
    config = ScanConfig(
        start_url=args.url if args.url else "",
        ip_target=args.ip,
        ports=ports_list,
        max_pages=args.max_pages,
        concurrency=args.workers,
        checks=args.checks,
        auth_jwt=args.auth_jwt,
        auth_cookie=args.auth_cookie,
        evasion_level=args.evasion
    )
    
    if args.ip:
        scanner = AsyncNetworkScanner(config)
        async def run() -> None:
            async with scanner:
                await scanner.scan_ports()
    else:
        if not config.start_url.startswith('http'):
            config.start_url = f'https://{config.start_url}'
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
    results = ReportGenerator.prepare_results(target_str, scanner)
    
    # Save JSON
    with open(args.report, 'w', encoding='utf-8') as f:
        f.write(ReportGenerator.generate_json(results))
        
    # Save Markdown
    md_file = args.report.replace('.json', '.md') if args.report.endswith('.json') else args.report + '.md'
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(ReportGenerator.generate_markdown(results))
        
    if args.ip:
        print(f"[+] Escaneo terminado. {getattr(scanner, 'ports_scanned_count', 0)} puertos verificados.")
    else:
        print(f"[+] Escaneo terminado. {len(getattr(scanner, 'visited', []))} páginas escaneadas.")
    print(f"[+] Reportes guardados: {args.report}, {md_file}")

if __name__ == "__main__":
    main()
