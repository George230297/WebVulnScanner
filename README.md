# WebVulnScanner
Scanner for search Web vulnerabilities 

Menú interactivo para configurar objetivo, checks, crawling, wordlist y opciones intrusivas.

Ejecuta run_checks del webvulnscanner_ext en un hilo de fondo y muestra logs en pantalla.

Permite ver y guardar el reporte JSON desde la TUI.

No requiere dependencias externas adicionales (usa curses que viene en la mayoría de distribuciones Linux).

Instrucciones rápidas para probarlo:

Colocar webvulnscanner_ext.py y webvulnscanner_tui.py en la misma carpeta.

Instalar dependencias del scanner: pip install requests beautifulsoup4

Ejecutar: python3 webvulnscanner_tui.py

Desde la UI, definir target, configurar y presionar R para lanzar el escaneo.
