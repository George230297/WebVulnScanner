# WebVulnScanner

## Licencias

![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![asyncio](https://img.shields.io/badge/asyncio-enabled-success.svg)
![aiohttp](https://img.shields.io/badge/aiohttp-async_HTTP-blueviolet.svg)
![Playwright](https://img.shields.io/badge/Playwright-DOM_Rendering-ff69b4.svg)
![Tests](https://img.shields.io/badge/tests-95%20passed-brightgreen.svg)

**Escáner de Vulnerabilidades Web Asíncrono y Modular**

WebVulnScanner es una herramienta avanzada de auditoría de seguridad diseñada para profesionales de ciberseguridad, pentesters y administradores de sistemas. Su objetivo es identificar fallos de seguridad comunes en aplicaciones web de manera rápida y eficiente utilizando un motor asíncrono de alto rendimiento.

## 🚀 Características Principales

- **Motor Asíncrono Absoluto**: Basado enteramente en `asyncio` y `aiohttp`, capaz de sostener y encolar cientos de peticiones sin agotar recursos.
- **Renderizado Dinámico de SPAs**: Integración nativa con `playwright` asíncrono para renderizar aplicaciones React, Vue o Angular de forma automatizada, aislando fugas de memoria y optimizando anchos de banda.
- **Evasión de WAF (Stealth Mode)**: Algoritmos de evasión y *bypass* de Rate Limits con Math Jitter (Ruido), Rotación biológica activa del User-Agent, y semáforos de Backoff exponencial anti-baneos permanentes.
- **Gestión Avanzada de Sesiones**: Administración global *Thread-Safe* con auto-refresh de tokens JWT, extracción dinámica de tokens CSRF y cookies persistentes desde áreas privadas de las web-apps.
- **Peritaje Threat Intelligence (CTI)**: Enriquecimiento automatizado en fase de post-procesamiento. Localiza vulnerabilidades subyacentes (CVEs) de tecnologías detectadas interactuando con bases públicas desde un motor local de concurrencia y caché.
- **Análisis Híbrido**: DAST (inyección en vivo) + SAST (estudio estático de fugas de secretos JS).
- **Reportes Enriquecidos**: Generación automática de reportes en JSON y Markdown, incluyendo severidades CVE.
- **Suite de Tests**: 95 pruebas unitarias e de integración con cobertura para componentes y módulos dinámicos.

## 🛠️ Instalación

Primero, clona el repositorio en tu máquina local:

```bash
git clone https://github.com/George230297/WebVulnScanner.git
cd WebVulnScanner
```

Luego, se recomienda instalar la herramienta en un entorno virtual:

```bash
python -m venv venv
# Activar entorno (Windows)
venv\Scripts\activate
# Activar entorno (Linux/Mac)
source venv/bin/activate

# Instalar dependencias (incluye playwright y otras utilidades)
pip install -r requirements.txt
playwright install chromium
```

> **Dependencias principales**: `aiohttp`, `playwright`, `beautifulsoup4`, `aiodns`  

## 💻 Uso

### Interfaz de Línea de Comandos (CLI)

```bash
# Auditar un objetivo limitando simultaneidad para evitar ban, ejecutando Stealth:
python run_scanner.py --url https://ejemplo.com --workers 50
```

Opciones disponibles:

- `--url`: URL objetivo (requerido).
- `--checks`: Lista de chequeos específicos (ej: `xss sqli`). Por defecto ejecuta todos.
- `--max-pages`: Límite de páginas a crawlear (default: 50).
- `--workers`: Número de hilos/conexiones concurrentes (default: 20).
- `--report`: Nombre del archivo de reporte (default: `report.json`).

### 📋 Ayuda y Comandos

| Argumento           | Descripción                                                   | Requerido |    Default    |
| :------------------ | :------------------------------------------------------------ | :-------: | :-----------: |
| `-h`, `--help`      | Muestra el mensaje de ayuda y termina.                        |    No     |       -       |
| `--url URL`         | URL objetivo para iniciar el escaneo.                         |  **Sí**   |       -       |
| `--checks [CHECKS]` | Lista de chequeos específicos a ejecutar (ej: `xss`, `sqli`). |    No     |     `all`     |
| `--max-pages N`     | Número máximo de páginas a visitar durante el crawling.       |    No     |     `50`      |
| `--workers N`       | Número de hilos/conexiones concurrentes.                      |    No     |     `20`      |
| `--report FILE`     | Nombre y ruta del archivo de reporte a generar.               |    No     | `report.json` |

## 🛡️ Capacidades de Detección

La versión actual incluye los siguientes plugins integrados:

1. **Reflected XSS**: Detección de Cross-Site Scripting reflejado mediante inyección y parseo.
2. **SQL Injection (Error-Based)**: Inyección y fuga SQL basada en errores base.
3. **Secrets Leak**: Búsqueda SAST de claves de AWS (`AKIA*`), Tokens, PEM privadas.
4. **Security Headers**: Auditoría analítica de cabeceras de respuesta (HSTS, CSP).
5. **Sensitive Files**: Descubrimiento de puntos expuestos. Combate falsos Soft 404s en implementaciones SPA.
6. **CSRF**: Inyección y evasión paralela de tokens *authenticity*.
7. **SSRF Candidates**: Forja de peticiones a nivel del lado del servidor.

## 📈 Tubería de Ejecución y Ecosistema (Core Engine V2)

En la versión más reciente, el orquestador (`engine.py`) ha sido profundamente rediseñado para acoplar nativamente 5 utilidades arquitectónicas de grado Enterprise. A continuación, el detalle del ciclo de vida interno de escaneo:

1. **Doble Escudo Heurístico (Soft404Profiler + SensitiveFileValidator)**: Antes de despachar el enjambre de hilos asíncronos en el `crawl_loop`, el motor ejecuta una calibración síncrona enviada a un sub-hilo independiente (`asyncio.to_thread`) para perfilar cómo responde el objetivo a archivos inexistentes. Extrae Hashes MD5 y longitudes DOM dinámicas. Luego, durante la ejecución asíncrona, cualquier hallazgo `200 OK` pasa primero por un Validador Heurístico de Capa 7 (`SensitiveFileValidator`) que rastrea firmas inyectables de React/Vue (`<div id="root">`) cruzando lógicas estrictas por extensión de archivo (ej. exigiendo sentencias `INSERT INTO` para validar volcados `.sql`). Esto asegura que el subsistema jamás reporte falsos ".env" o "config.php" engañosos provistos por WAFs o balanceadores traicioneros.
2. **Intercepción de Transporte (`StealthManager`)**: El escáner ya no invoca peticiones de forma descubierta. En la etapa de Fetch, el núcleo inyecta la función `async_request` en un *wrapper* de protección ofensiva. Ésta envuelve el tráfico asíncrono aplicando retardos estocásticos de simulación humana (Jitter), rotando aleatoriamente entre 10 User-Agents reales en cada milisegundo, y gestionando Locks automáticos por subdominio si se intercepta un baneo **HTTP 429** o **403**. Todo el ecosistema de *plugins* queda resguardado mágicamente tras contadores de BackOff exponencial lineal de reintento.
3. **Persistencia Dinámica de Cuentas (`SessionManager`)**: Autentificación `Thread-Safe` universal. El motor inyecta automáticamente variables CSRF detectadas al vuelo en nuevas peticiones, absorbiendo tokens desde el DOM cada vez que se detecta un `200 OK`. Si a mitad del ciclo (que puede tardar horas) el cortafuegos expira el certificado (JWT/Cookie), el motor usa el cerrojo global para paralizar el escaneo, ejecuta asíncronamente un "Auto-Login" provisto por el Pentester (Callback), restablece las cabeceras a la RAM limpia, y despacha en cascada los cientos de hilos reanudados sin perder un solo escaneo.
4. **Extracción en SPAs In-flight (`DynamicRenderer`)**: El analizador estático ya no se detiene ante React/Vue. Al interceptar fragmentos biológicos como `<div id="root">` en las respuestas crudas directas, el orquestador reanima asíncronamente a Chromium `Playwright` bajo Context Managers blindados para compilar los scripts locales, inyectando variables HTML enriquecidas al resto del motor y abortando en el núcleo *assets* pesados .css o .jpg para no penalizar la red.
5. **Resolución Ofensiva CTI (`ThreatIntelEnricher`)**: Una vez colapsada la cola de escaneo activo (`queue.empty()`), el Engine extrajo pasivamente en las cabeceras `Server` una lista masiva de tecnologías. Se traspasa en Fase Final al Enriquecedor, el cual de forma totalmente asíncrona pero limitada por un Semáforo anti-rate limit, cruza la data local con APIs de Amenazas, deduplicando redundancias idénticas al milisegundo con *in-flight locks* de memoria, y listando `CVEs` certificados directos al Reporte Final (JSON/Markdown).

## 🏗️ Arquitectura y Diseño Orientado a Componentes

El proyecto se sustenta en una arquitectura modular fundamentada en el **Patrón Strategy** inyectado a una batería de Middlewares de red avanzados.

### Diagrama de Clases y Flujo (UML)

```mermaid
classDiagram
    class CLI {
        +main()
        +parse_args()
    }
    class Engine {
        +run_scan(url, checks)
        +fetch(url, param)
        +crawl_loop()
    }
    class StealthManager {
        +execute_with_stealth()
        +apply_jitter()
    }
    class SessionManager {
        +load_raw_cookie()
        +set_jwt()
        +extract_csrf_token()
        +handle_auto_refresh()
    }
    class Network {
        +init_network()
        +async_request()
    }
    class DynamicRenderer {
        +render_dom(url)
    }
    class ThreatIntelEnricher {
        +enrich_findings_batch()
    }
    class Soft404Profiler {
        +calibrate_target()
        +is_soft_404()
    }
    class SensitiveFileValidator {
        +is_real_sensitive_file()
    }
    class BaseCheck {
        <<interface>>
        +name: str
        +check(url, response)*
    }

    CLI --> Engine : Parse Argumentos e inyecta Config
    Engine --> SessionManager : Configura Headers y Autenticación Global
    Engine --> SensitiveFileValidator : Nivel 1: Filtro Heurístico DOM
    Engine --> Soft404Profiler : Nivel 2: Calibración Temprana MD5
    Engine --> StealthManager : Delega Peticiones Ofensivas al Interceptor
    StealthManager --> Network : Envuelve a la capa asyncio nativa  
    Engine --> DynamicRenderer : Reanima DOM en React/Vue
    Engine "1" *-- "*" BaseCheck : Carga Interfaces dinámicamente (Type Strategy)
    BaseCheck --> SessionManager : El Plugin asimila y detecta extractores
    Engine --> ThreatIntelEnricher : Intercambio de Data CTI en Post-Procesamiento (CVEs)
    Engine --> Formatter : Entrega Vulnerabilidades estructuradas
```

### Principios Fundamentales
1. **Separación de Responsabilidades (SoC):** El motor se abstrae completamente del ataque, concentrándose puramente en la encolación masiva en grafos. El módulo `Network` tampoco conoce al WAF, es envuelto quirúrgicamente por `StealthManager`.
2. **Abierto a Extensión:** Agniadir soporte para esquemas avanzados de reautenticación o interconectar APIs privadas propietarias sobre el `ThreatIntelEnricher` no demanda ninguna refactorización a `BaseCheck` ni obliga a romper la estabilidad inmensamente testeada (95/95 Unit Tests) de los middlewares centrales.

## ⚖️ Licencia

Este proyecto está licenciado bajo la **Licencia MIT**.

## ⚠️ DESCARGO DE RESPONSABILIDAD (DISCLAIMER)

Esta herramienta ha sido desarrollada **exclusivamente con fines educativos y de auditoría de seguridad autorizada**. WebVulnScanner ayuda a administradores y analistas a identificar fugas y errores operacionales propios. Su uso ilícito contra un patrimonio informático ajeno no autorizado penaliza severamente por la ley y **es responsabilidad unívoca del ejecutor directo**.
