# WebVulnScanner

Herramienta principal: webvulnscanner_ext.py (CLI).

Interfaz TUI: webvulnscanner_tui.py (terminal, Linux).

Instalación opcional como comandos: webvulnscanner y webvulnscanner-tui (vía setup.py).

Seguridad: las pruebas intrusivas requieren flags --allow-intrusive y --authorized. Úsalo sólo en sistemas autorizados.

# Requisitos previos (Linux):

Python 3.8+ (recomendado 3.8–3.11).

pip y virtualenv (recomendado).

(Opcional) sqlmap si quieres integración con sqlmap.

(Opcional) msfrpcd corriendo si vas a usar Metasploit (para la UI que integra MSF).

Para la TUI: una terminal compatible con curses (Linux / WSL2 con terminal moderno).

Docker (opcional, para pruebas en laboratorios locales).

# Preparar el entorno (recomendado):

crear virtualenv (opcional pero recomendado)
python3 -m venv venv
source venv/bin/activate

instalar dependencias básicas
python3 -m pip install --upgrade pip
python3 -m pip install requests beautifulsoup4

Coloca estos archivos en la misma carpeta:

webvulnscanner_ext.py

webvulnscanner_tui.py

setup.py (opcional, para instalar comandos)

Instalar la herramienta como comandos (opcional, recomendado)

esto crea los comandos webvulnscanner y webvulnscanner-tui.

# Desde la carpeta que contiene setup.py, webvulnscanner_ext.py y webvulnscanner_tui.py
python3 -m pip install -e .
ahora deberías tener:
- webvulnscanner
- webvulnscanner-tui

Si no quieres instalar, puedes ejecutar los scripts directamente con python3 webvulnscanner_ext.py ... y python3 webvulnscanner_tui.py.

# Uso: CLI (rápido)

Ejecuta un escaneo básico (no intrusivo):

Escaneo básico, solo checks no intrusivos y sin crawling
webvulnscanner --url https://example.com --report out.json

Escaneo con crawling (más completo, más tráfico)
webvulnscanner --url https://example.com --crawl --max-pages 100 --workers 10 --report out.json


Ejecutar con integración sqlmap (intrusivo — requiere autorización):

webvulnscanner --url https://example.com --crawl --use-sqlmap --sqlmap-options "--level 2" "--risk 1" --allow-intrusive --authorized --report sqlmap_report.json

Importante: --allow-intrusive y --authorized son obligatorios para pruebas intrusivas.

# Uso: TUI (desde consola Linux)
si instalaste via setup.py
webvulnscanner-tui

si no lo instalaste
python3 webvulnscanner_tui.py

# En la TUI:

-E editar target → escribe la URL (la TUI sugiere https:// si falta).

-T historial → selección rápida de objetivos previos.

-C toggle checks (escribe prefijo y la UI sugiere nombres).

-L toggle crawl, -D toggle dir brute, -S toggle sqlmap.

-I toggle allow-intrusive, -A toggle authorized (ambos deben estar activados para intrusivos).

-R run scan, -V ver reporte en pantalla, -W guardar reporte JSON.

-Q salir.

La TUI guarda historial en ~/.webvulnscanner_history.json.

#Probar la herramienta en entornos seguros (laboratorios locales)

Opción A — OWASP Juice Shop (Docker)

docker run --rm -p 3000:3000 bkimminich/juice-shop
Accede a http://localhost:3000 para ver la app vulnerable

Ejecuta scanner apuntando a http://localhost:3000
webvulnscanner --url http://localhost:3000 --crawl --max-pages 50 --report juice_report.json

Opción B — DVWA (Damn Vulnerable Web App) (Docker)

Ejemplo de imagen común; adáptalo según tu repositorio
docker run --rm -it -p 80:80 vulnerables/web-dvwa

Apunta el scanner a http://localhost (o puerto mapeado)
webvulnscanner --url http://localhost --crawl --report dvwa_report.json

Siempre usa laboratorios locales o entornos aprobados (no escanees terceros sin permiso).
