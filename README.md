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
