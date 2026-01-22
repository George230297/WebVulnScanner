# Usamos una imagen base ligera de Python
FROM python:3.11-slim

# Definimos variables de entorno:
# - PYTHONDONTWRITEBYTECODE: Evita crear archivos .pyc innecesarios
# - PYTHONUNBUFFERED: Asegura que los logs salgan inmediatamente a la consola
# - TERM: Necesario para que la interfaz TUI (curses) se vea bien y con colores
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# (Opcional) Instalamos dependencias del sistema si fueran necesarias para compilar
# RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copiamos los archivos de tu proyecto al contenedor
COPY setup.py .
COPY webvulnscanner_ext.py .
COPY webvulnscanner_tui.py .
# Si tienes un README o requirements, podrías copiarlos también, pero con esto basta.

# Instalamos la herramienta y sus dependencias (aiohttp, requests, etc.)
RUN pip install --no-cache-dir -e .

# Por defecto, al entrar, abrimos una shell bash.
# Esto nos permite elegir si queremos correr la CLI o la TUI manualmente.
CMD ["/bin/bash"]