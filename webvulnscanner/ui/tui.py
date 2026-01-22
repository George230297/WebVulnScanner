import curses
import threading
import asyncio
import traceback
from time import sleep

from webvulnscanner.config import ScanConfig
from webvulnscanner.core.engine import AsyncScanner
from webvulnscanner.ui.cli import prepare_results

class ScannerState:
    def __init__(self):
        self.target = ''
        self.checks = {'xss': True, 'sqli': True, 'csrf': True, 'secrets': True, 'ssrf': True}
        self.crawl = True
        self.max_pages = 100
        self.workers = 20
        self.report = None
        self.report_path = 'webvuln_report_tui.json'
        self.log_lines = []
        self.running = False
        self.pages_scanned = 0

    def log(self, msg):
        self.log_lines.append(msg)
        if len(self.log_lines) > 200:
            self.log_lines.pop(0)

state = ScannerState()

def run_scan_wrapper(st):
    st.running = True
    st.log("Iniciando motor asíncrono modular...")
    
    try:
        # Configurar
        chk_list = [k for k,v in st.checks.items() if v]
        config = ScanConfig(
            start_url=st.target if st.target.startswith('http') else f'https://{st.target}',
            max_pages=st.max_pages,
            concurrency=st.workers,
            checks=chk_list
        )
        
        scanner = AsyncScanner(config)
        
        # Monitor de progreso simple
        # Como asyncio.run bloquea, no podemos leer scanner.visited fácilmente desde fuera 
        # a menos que pasemos un callback o usemos una tarea global.
        # Para simplificar, confiaremos en que termine.
        
        async def _run():
             async with scanner:
                 # Monkey patch o callback para logging si quisiéramos
                 await scanner.crawl_loop()
        
        asyncio.run(_run())
        
        res = prepare_results(st.target, scanner)
        st.report = res
        st.pages_scanned = len(scanner.visited)
        
        # Conteo de vulns
        vuln_count = sum(len(v) for v in res['checks'].values())
        st.log(f"Finalizado. {st.pages_scanned} páginas. {vuln_count} vulnerabilidades.")
        
    except Exception as e:
        st.log(f"Error: {e}")
        st.log(traceback.format_exc())
    finally:
        st.running = False

def draw_menu(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True) # Non-blocking input handling
    stdscr.timeout(100)  # Refresh every 100ms
    
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        
        # Header
        stdscr.addstr(0, 2, 'WebVulnScanner v2.1 - Modular TUI', curses.A_BOLD | curses.A_REVERSE)
        
        status = "EJECUTANDO" if state.running else "IDLE"
        stdscr.addstr(1, 2, f'Estado: {status} | Paginas: {state.pages_scanned}')

        # Input Info
        stdscr.addstr(3, 4, f'Target: {state.target if state.target else "[Vacío]"}')
        
        # Checks
        stdscr.addstr(5, 4, 'Checks Activos:')
        checks_list = list(state.checks.items())
        for i, (kname, kval) in enumerate(checks_list):
            mk = '[X]' if kval else '[ ]'
            stdscr.addstr(6 + i, 6, f'{mk} {kname}')

        next_y = 6 + len(checks_list) + 2
        stdscr.addstr(next_y, 4, f'Max Pages: {state.max_pages} | Concurrency: {state.workers}')

        # Controles
        stdscr.addstr(next_y+3, 2, 'Controles:', curses.A_UNDERLINE)
        stdscr.addstr(next_y+4, 4, '[E] Editar URL   [R] RUN SCAN   [Q] Salir')
        
        # Logs
        stdscr.addstr(next_y+6, 2, 'Logs:')
        log_h = h - (next_y+8)
        if log_h > 0:
            for i, line in enumerate(state.log_lines[-log_h:]):
                try:
                    stdscr.addstr(next_y+7+i, 4, line[:w-5])
                except: pass

        stdscr.refresh()
        
        try:
            ch = stdscr.getch()
        except:
            ch = -1
            
        if ch == -1: continue
        
        if ch in [ord('q'), ord('Q')]: break
        elif ch in [ord('e'), ord('E')]:
            curses.echo()
            stdscr.nodelay(False)
            stdscr.addstr(next_y+4, 25, " " * 40)
            stdscr.addstr(next_y+4, 25, "URL: ")
            try:
                t = stdscr.getstr(next_y+4, 30).decode('utf-8').strip()
                state.target = t
                state.log(f"Target set: {t}")
            except: pass
            curses.noecho()
            stdscr.nodelay(True)
        elif ch in [ord('r'), ord('R')]:
            if not state.target:
                state.log("Error: Falta Target")
            elif state.running:
                state.log("Ya está corriendo")
            else:
                t = threading.Thread(target=run_scan_wrapper, args=(state,))
                t.daemon = True
                t.start()

def main():
    try:
        curses.wrapper(draw_menu)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
