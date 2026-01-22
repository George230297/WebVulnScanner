#!/usr/bin/env python3
"""
WebVulnScanner TUI - Interfaz actualizada para v2
"""

import curses
import json
import threading
import traceback
import sys
from pathlib import Path

# Import dinámico del core
# Import dinámico del core
try:
    from Web_Vuln_Scanner import run_checks
except ImportError:
    import importlib.util
    p = Path(__file__).parent / 'Web_Vuln_Scanner.py'
    if p.exists():
        spec = importlib.util.spec_from_file_location('Web_Vuln_Scanner', str(p))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run_checks = module.run_checks
    else:
        run_checks = None

class ScannerState:
    def __init__(self):
        self.target = ''
        # Agregamos 'secrets' a los checks por defecto
        self.checks = {'xss': True, 'sqli': True, 'csrf': True, 'secrets': True, 'ssrf': True}
        self.crawl = True
        self.max_pages = 100
        self.workers = 20 # Async permite más concurrencia por defecto
        self.allow_intrusive = False
        self.authorized = False
        self.report = None
        self.report_path = 'webvuln_report_tui.json'
        self.log_lines = []
        self.running = False

    def log(self, msg):
        self.log_lines.append(msg)
        if len(self.log_lines) > 200:
            self.log_lines.pop(0)

state = ScannerState()

def draw_menu(stdscr):
    curses.curs_set(0)
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        
        # Header
        stdscr.addstr(0, 2, 'WebVulnScanner v2 - TUI (Async Engine)', curses.A_BOLD | curses.A_REVERSE)
        stdscr.addstr(1, 2, 'Motor asíncrono activo con análisis JS estático')

        # Info Principal
        stdscr.addstr(3, 4, f'Target: {state.target if state.target else "[Vacío]"}')
        
        # Checks
        stdscr.addstr(5, 4, 'Checks Activos:')
        checks_list = list(state.checks.items())
        for i, (kname, kval) in enumerate(checks_list):
            mk = '[X]' if kval else '[ ]'
            stdscr.addstr(6 + i, 6, f'{mk} {kname}')

        next_y = 6 + len(checks_list) + 2
        stdscr.addstr(next_y, 4, f'Crawl: {"ON" if state.crawl else "OFF"} | Max Pages: {state.max_pages} | Concurrency: {state.workers}')
        stdscr.addstr(next_y+1, 4, f'Intrusivo: {"PERMITIDO" if state.allow_intrusive else "BLOQUEADO"} | Autorizado: {"SI" if state.authorized else "NO"}')

        # Controles
        stdscr.addstr(next_y+3, 2, 'Controles:', curses.A_UNDERLINE)
        stdscr.addstr(next_y+4, 4, '[E] Editar URL   [C] Toggle Check   [R] RUN SCAN')
        stdscr.addstr(next_y+5, 4, '[I] Toggle Intrusive   [A] Toggle Authorized')
        stdscr.addstr(next_y+6, 4, '[V] Ver Reporte   [W] Guardar JSON   [Q] Salir')

        # Logs Area
        stdscr.addstr(next_y+8, 2, 'Logs:')
        log_h = h - (next_y+10)
        if log_h > 0:
            for i, line in enumerate(state.log_lines[-log_h:]):
                stdscr.addstr(next_y+9+i, 4, line[:w-5])

        stdscr.refresh()
        
        ch = stdscr.getch()
        
        if ch in [ord('q'), ord('Q')]: break
        elif ch in [ord('e'), ord('E')]:
            curses.echo()
            stdscr.addstr(next_y+4, 25, " " * 40)
            stdscr.addstr(next_y+4, 25, "URL: ")
            try:
                t = stdscr.getstr(next_y+4, 30).decode('utf-8').strip()
                state.target = t
                state.log(f"Target set: {t}")
            except: pass
            curses.noecho()
        elif ch in [ord('c'), ord('C')]:
            # Simple toggle rotativo para demo
            ks = list(state.checks.keys())
            # Lógica simplificada: togglear el primero que esté off, o rotar
            pass # Implementar selector si se desea, para brevedad
        elif ch in [ord('i'), ord('I')]:
            state.allow_intrusive = not state.allow_intrusive
            state.log(f"Intrusive: {state.allow_intrusive}")
        elif ch in [ord('a'), ord('A')]:
            state.authorized = not state.authorized
            state.log(f"Authorized: {state.authorized}")
        elif ch in [ord('r'), ord('R')]:
            if not state.target:
                state.log("Error: Falta Target")
            elif state.running:
                state.log("Ya está corriendo")
            else:
                t = threading.Thread(target=run_scan_background, args=(state,))
                t.daemon = True
                t.start()
        elif ch in [ord('v'), ord('V')]:
            view_report(stdscr)
        elif ch in [ord('w'), ord('W')]:
            save_report_to_file()

def run_scan_background(st):
    st.running = True
    st.log("Iniciando motor asíncrono...")
    try:
        # Simulamos objeto opts
        class Opts: pass
        o = Opts()
        o.checks = [k for k,v in st.checks.items() if v]
        o.max_pages = st.max_pages
        o.workers = st.workers
        o.allow_intrusive = st.allow_intrusive
        o.authorized = st.authorized
        
        rep = run_checks(st.target, o)
        st.report = rep
        st.log(f"Finalizado. Vulns encontradas: {sum(len(v) for v in rep['checks'].values())}")
    except Exception as e:
        st.log(f"Error: {e}")
        st.log(traceback.format_exc())
    finally:
        st.running = False

def view_report(stdscr):
    # Reutilizar lógica original de visualización
    pass 

def save_report_to_file():
    if state.report:
        with open(state.report_path, 'w') as f:
            json.dump(state.report, f, indent=2)
        state.log(f"Guardado en {state.report_path}")

def main():
    curses.wrapper(draw_menu)

if __name__ == '__main__':
    main()