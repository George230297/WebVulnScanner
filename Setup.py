# setup.py
from setuptools import setup

setup(
    name='webvulnscanner',
    version='0.1.0',
    py_modules=['webvulnscanner_ext', 'webvulnscanner_tui'],
    install_requires=['requests', 'beautifulsoup4'],
    entry_points={
        'console_scripts': [
            'webvulnscanner = webvulnscanner_ext:main_cli',
            'webvulnscanner-tui = webvulnscanner_tui:main'
        ]
    },
    description='WebVulnScanner - herramienta para evaluación de aplicaciones web (CLI + TUI)',
    author='Tu nombre',
)

# Instrucciones de instalación:
# 1. Colocar webvulnscanner_ext.py y webvulnscanner_tui.py en el mismo directorio que este setup.py
# 2. Instalar en modo editable (recomendado durante desarrollo):
#    python3 -m pip install -e .
# 3. Ejecutar desde la consola:
#    webvulnscanner --url https://example.com --crawl
#    webvulnscanner-tui
