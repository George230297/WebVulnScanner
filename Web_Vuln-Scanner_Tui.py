#!/usr/bin/env python3
"""
WebVulnScanner TUI - Interfaz de texto (curses) para entornos Linux

Descripción
-----------
Interfaz TUI ligera basada en curses para lanzar WebVulnScanner desde la consola.
Permite:
 - Introducir objetivo (URL)
 - Seleccionar checks (xss, sqli, csrf, openredirect, ssrf, rce)
 - Habilitar crawling, brute-force de directorios y sqlmap (con autorización)
 - Lanzar el escaneo y seguir progreso básico (mensajes) en pantalla
 - Ver el reporte actualizado y guardarlo en archivo JSON

Requisitos
---------
 - Linux (o terminal compatible con curses)
 - Python 3.8+
 - webvulnscanner_ext.py en el mismo directorio (o módulo instalable)
 - pip install requests beautifulsoup4  (para webvulnscanner_ext)

Uso
---
python3 webvulnscanner_tui.py

Nota: la TUI no ejecuta nada por sí sola hasta que pulses "Run scan". Las pruebas intrusivas requieren marcar
--allow-intrusive y --authorized (la UI pedirá confirmación si activas esas opciones).

Limitaciones
-----------
- Interfaz simple pensada para terminal. No requiere dependencias externas aparte de las del scanner.
- Para obtener salida más rica (logs, xml de nmap, salida de sqlmap) abre el archivo de reporte generado.
"""

import curses
import json
import threading
import traceback
from pathlib import Path

# Intentamos importar el orquestador extendido
try:
    from webvulnscanner_ext import run_checks
except Exception:
    # Si no está instalado como módulo, intentamos carga por path
    import importlib.util
    import sys
    p = Path(__file__).parent / 'webvulnscanner_ext.py'
    if p.exists():
        spec = importlib.util.spec_from_file_location('webvulnscanner_ext', str(p))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run_checks = module.run_checks
    else:
        run_checks = None


class ScannerState:
    def __init__(self):
        self.target = ''
        self.checks = {'xss': True, 'sqli': True, 'csrf': True, 'openredirect': True, 'ssrf': True, 'rce': True}
        self.crawl = True
        self.max_pages = 100
        self.workers = 10
        self.dir_bruteforce = False
        self.wordlist = ''
        self.use_sqlmap = False
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
    k = 0
    cursor_y = 2

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        stdscr.addstr(0, 2, 'WebVulnScanner - TUI (Linux)', curses.A_BOLD)
        stdscr.addstr(1, 2, 'Use flechas para navegar, Enter para editar, R para ejecutar, Q para salir')

        # Target
        stdscr.addstr(3, 4, f'Target: {state.target}')
        # Checks
        stdscr.addstr(5, 4, 'Checks:')
        checks_list = list(state.checks.items())
        for i, (kname, kval) in enumerate(checks_list):
            marker = '[x]' if kval else '[ ]'
            stdscr.addstr(6 + i, 6, f'{marker} {kname}')

        y = 6 + len(checks_list) + 1
        stdscr.addstr(y, 4, f'Crawl: {"ON" if state.crawl else "OFF"}  (max_pages={state.max_pages}, workers={state.workers})')
        stdscr.addstr(y+1, 4, f'Dir bruteforce: {"ON" if state.dir_bruteforce else "OFF"}  Wordlist: {state.wordlist or "(default)"}')
        stdscr.addstr(y+2, 4, f'Use sqlmap: {"ON" if state.use_sqlmap else "OFF"}  Intrusivo permitido: {state.allow_intrusive and state.authorized}')

        # Controls
        stdscr.addstr(y+4, 4, '[E] Edit target   [C] Toggle check   [L] Toggle crawl   [D] Toggle dir brute   [S] Toggle sqlmap')
        stdscr.addstr(y+5, 4, '[I] Toggle allow-intrusive   [A] Toggle authorized   [R] Run scan   [V] View report   [W] Save report')
        stdscr.addstr(y+6, 4, '[Q] Quit')

        # Logs
        stdscr.addstr(y+8, 2, 'Logs:')
        log_h = height - (y+11)
        for i, line in enumerate(state.log_lines[-log_h:]):
            stdscr.addstr(y+9 + i, 4, line[:width-8])

        stdscr.refresh()

        ch = stdscr.getch()
        if ch == ord('q') or ch == ord('Q'):
            break
        elif ch == ord('e') or ch == ord('E'):
            curses.echo()
            stdscr.addstr(y+3, 4, 'Target (enter URL): ')
            t = stdscr.getstr(y+3, 25, 80).decode('utf-8').strip()
            state.target = t
            curses.noecho()
            state.log(f'Set target: {t}')
        elif ch == ord('c') or ch == ord('C'):
            # toggle a check chosen by user
            curses.echo()
            stdscr.addstr(y+3, 4, 'Toggle which check? (xss/sqli/csrf/openredirect/ssrf/rce): ')
            what = stdscr.getstr(y+3, 62, 20).decode('utf-8').strip()
            curses.noecho()
            if what in state.checks:
                state.checks[what] = not state.checks[what]
                state.log(f'Toggle {what} -> {state.checks[what]}')
            else:
                state.log('Check name invalid')
        elif ch == ord('l') or ch == ord('L'):
            state.crawl = not state.crawl
            state.log(f'Crawl -> {state.crawl}')
        elif ch == ord('d') or ch == ord('D'):
            state.dir_bruteforce = not state.dir_bruteforce
            state.log(f'Dir bruteforce -> {state.dir_bruteforce}')
        elif ch == ord('s') or ch == ord('S'):
            state.use_sqlmap = not state.use_sqlmap
            state.log(f'Use sqlmap -> {state.use_sqlmap}')
        elif ch == ord('i') or ch == ord('I'):
            state.allow_intrusive = not state.allow_intrusive
            state.log(f'Allow intrusive -> {state.allow_intrusive}')
        elif ch == ord('a') or ch == ord('A'):
            state.authorized = not state.authorized
            state.log(f'Authorized -> {state.authorized}')
        elif ch == ord('r') or ch == ord('R'):
            if not run_checks:
                state.log('run_checks no disponible. Asegure webvulnscanner_ext.py está en el mismo directorio.')
            elif state.running:
                state.log('Scan ya en ejecución')
            elif not state.target:
                state.log('Defina target primero')
            else:
                # preguntar confirmación si intrusivo
                if state.use_sqlmap or state.allow_intrusive:
                    if not (state.allow_intrusive and state.authorized):
                        state.log('Opciones intrusivas requieren --allow-intrusive y --authorized. Actívelas antes.')
                        continue
                t = threading.Thread(target=run_scan_background, args=(state,))
                t.daemon = True
                t.start()
        elif ch == ord('v') or ch == ord('V'):
            view_report(stdscr)
        elif ch == ord('w') or ch == ord('W'):
            save_report_to_file()


def run_scan_background(state: ScannerState):
    state.running = True
    state.log('Iniciando escaneo...')
    class Opts:
        pass
    opts = Opts()
    opts.crawl = state.crawl
    opts.max_pages = state.max_pages
    opts.workers = state.workers
    opts.checks = [k for k, v in state.checks.items() if v]
    opts.dir_bruteforce = state.dir_bruteforce
    opts.wordlist = state.wordlist or None
    opts.use_sqlmap = state.use_sqlmap
    opts.sqlmap_options = []
    opts.allow_intrusive = state.allow_intrusive
    opts.authorized = state.authorized

    try:
        report = run_checks(state.target, opts)
        state.report = report
        state.log('Escaneo finalizado')
    except Exception as ex:
        state.log('Error durante escaneo: ' + str(ex))
        state.log(traceback.format_exc())
    finally:
        state.running = False


def view_report(stdscr):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.addstr(0, 2, 'Reporte actual (presione cualquier tecla para volver)')
    if not state.report:
        stdscr.addstr(2, 2, 'No hay reporte disponible. Ejecute un escaneo primero.')
        stdscr.getch()
        return
    text = json.dumps(state.report, indent=2, ensure_ascii=False)
    lines = text.splitlines()
    h, w = stdscr.getmaxyx()
    max_lines = h - 3
    pos = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 2, 'Reporte actual (flechas para navegar, Q para salir)')
        for i in range(min(max_lines, len(lines) - pos)):
            stdscr.addstr(2 + i, 2, lines[pos + i][:w-4])
        ch = stdscr.getch()
        if ch == curses.KEY_DOWN:
            if pos + max_lines < len(lines):
                pos += 1
        elif ch == curses.KEY_UP:
            if pos > 0:
                pos -= 1
        elif ch == ord('q') or ch == ord('Q') or ch != -1:
            break


def save_report_to_file():
    if not state.report:
        state.log('No hay reporte para guardar')
        return
    try:
        with open(state.report_path, 'w', encoding='utf-8') as f:
            json.dump(state.report, f, indent=2, ensure_ascii=False)
        state.log(f'Reporte guardado en {state.report_path}')
    except Exception as ex:
        state.log('No se pudo guardar reporte: ' + str(ex))


def main():
    curses.wrapper(draw_menu)


if __name__ == '__main__':
    main()
