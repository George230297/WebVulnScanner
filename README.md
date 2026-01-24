# WebVulnScanner

**Escáner de Vulnerabilidades Web Asíncrono y Modular**

WebVulnScanner es una herramienta avanzada de auditoría de seguridad diseñada para profesionales de ciberseguridad, pentesters y administradores de sistemas. Su objetivo es identificar fallos de seguridad comunes en aplicaciones web de manera rápida y eficiente utilizando un motor asíncrono de alto rendimiento.

## 🚀 Características Principales

- **Motor Asíncrono**: Basado en `asyncio` y `aiohttp`, capaz de realizar cientos de peticiones concurrentes sin bloquear el sistema.
- **Arquitectura Modular**: Sistema de plugins extensible. Añade nuevas detecciones sin modificar el núcleo.
- **Análisis Híbrido**:
  - **DAST (Dynamic Analysis)**: Inyección de payloads para XSS y SQLi en tiempo real.
  - **SAST (Static Analysis)**: Análisis de archivos JavaScript (`.js`) para detectar secretos hardcodeados (API Keys, Tokens) y endpoints ocultos.
- **Seguridad Mejorada**: Verificación robusta de SSL/TLS y validación estricta de regex para reducir falsos positivos.
- **Detección de WAF**: Identificación básica de Firewalls de Aplicación Web.
- **Reportes**: Generación automática de reportes en JSON y Markdown.
- **Interfaz Unificada**: Uso simplificado a través de un único punto de entrada CLI.

## 🛠️ Instalación

Se recomienda instalar la herramienta en un entorno virtual:

```bash
# Crear entorno virtual
python -m venv venv
# Activar entorno (Windows)
venv\Scripts\activate
# Activar entorno (Linux/Mac)
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## 💻 Uso

### Interfaz de Línea de Comandos (CLI)

Para un escaneo rápido y directo utilice el script principal:

```bash
python Web_Vuln_Scanner.py --url https://ejemplo.com --workers 50
```

Opciones disponibles:

- `--url`: URL objetivo (requerido).
- `--checks`: Lista de chequeos específicos (ej: `xss sqli`). Por defecto ejecuta todos.
- `--max-pages`: Límite de páginas a crawlear (default: 50).
- `--workers`: Número de hilos/conexiones concurrentes (default: 20).
- `--report`: Nombre del archivo de reporte (default: `report.json`).

### Ejemplo de uso modular

```bash
# Ejecutar solo checks de secretos y headers
python Web_Vuln_Scanner.py --url https://target.com --checks secrets headers
```

## 🛡️ Capacidades de Detección

La versión actual incluye los siguientes módulos (plugins):

1.  **Reflected XSS**: Detección de Cross-Site Scripting reflejado.
2.  **SQL Injection (Error-Based)**: Inyección SQL basada en errores de base de datos.
3.  **Secrets Leak**: Búsqueda de claves API (AWS, Google, etc.) en código fuente y JS.
4.  **Security Headers**: Auditoría de cabeceras de seguridad faltantes (HSTS, CSP, etc.).
5.  **Sensitive Files**: Detección de archivos expuestos (`.env`, `.git`, backups).
6.  **CSRF**: Análisis heurístico de formularios sin tokens anti-CSRF.
7.  **SSRF Candidates**: Identificación de parámetros sospechosos de Server-Side Request Forgery.

## ⚖️ Licencia

Este proyecto está licenciado bajo la **Licencia MIT**.

```text
MIT License

Copyright (c) 2026 [Tu Nombre / Organización]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ⚠️ DESCARGO DE RESPONSABILIDAD (DISCLAIMER)

**LEER ATENTAMENTE ANTES DE USAR:**

Esta herramienta ha sido desarrollada **exclusivamente con fines educativos y de auditoría de seguridad autorizada**. El objetivo de WebVulnScanner es ayudar a administradores y desarrolladores a identificar y corregir vulnerabilidades en sus propios sistemas.

- **Uso No Autorizado**: El uso de esta herramienta contra objetivos o infraestructuras sin el consentimiento previo, explícito y por escrito de sus propietarios es **ILEGAL** y está estrictamente prohibido.
- **Responsabilidad**: El autor y los contribuidores de este proyecto **NO se hacen responsables** de ningún mal uso, daño, pérdida de datos o consecuencias legales derivadas de la utilización de esta herramienta.
- **Bajo su propio riesgo**: El usuario asume toda la responsabilidad por las acciones realizadas con este software.

**Si no estás seguro de tener permiso para escanear un sitio web, NO LO HAGAS.**
