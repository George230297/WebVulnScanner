# WebVulnScanner

## Licencias

![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![asyncio](https://img.shields.io/badge/asyncio-enabled-success.svg)
![aiohttp](https://img.shields.io/badge/aiohttp-async_HTTP-blueviolet.svg)
![Playwright](https://img.shields.io/badge/Playwright-DOM_Rendering-ff69b4.svg)
![Tests](https://img.shields.io/badge/tests-101%20passed-brightgreen.svg)

**Escáner de Vulnerabilidades Web Asíncrono y Modular**

WebVulnScanner es una herramienta avanzada de auditoría de seguridad diseñada para profesionales de ciberseguridad, pentesters y administradores de sistemas. Su objetivo es identificar fallos de seguridad comunes en aplicaciones web de manera rápida y eficiente utilizando un motor asíncrono de alto rendimiento.

## 🚀 Características Principales

- **Motor Asíncrono Absoluto**: Basado enteramente en `asyncio` y `aiohttp`, capaz de sostener y encolar cientos de peticiones sin agotar recursos.
- **Renderizado Dinámico de SPAs (Cross-Platform Bypass)**: Integración nativa con `playwright` asíncrono. Soporte inteligente de conmutación de arquitectura: utiliza Chromium empotrado en Windows/Mac, o se engancha silenciosamente al binario nativo de penetración de Kali Linux (`/usr/bin/chromium`) para renderizar aplicaciones React, Vue o Angular de forma automatizada, optimizando recursos a nivel sistema operativo.
- **Evasión de WAF (Stealth Mode) de Grado Militar**: Algoritmos avanzados de evasión L7 con rotación auto-sanable de Proxies (SOCKS/HTTP), Falsificación de Identidad (Spoofing de IPs internas), Fragmentación Acústica de tráfico HTTP Chunked, y mutación de Payloads polimórficos (`WafEncoder`). Incluye simulación humana (Math Jitter) automático anti-baneos permanentes.
- **Gestión Avanzada de Sesiones**: Administración global *Thread-Safe* con auto-refresh de tokens JWT, extracción dinámica de tokens CSRF y cookies persistentes desde áreas privadas de las web-apps.
- **Peritaje Threat Intelligence (CTI)**: Enriquecimiento automatizado en fase de post-procesamiento. Localiza vulnerabilidades subyacentes (CVEs) de tecnologías detectadas interactuando con bases públicas desde un motor local de concurrencia y caché.
- **Análisis Híbrido Avanzado (DAST/SAST)**: Motor profundo de Inyección Dinámica (DAST) capaz de extraer Formularios DOM, adivinar parámetros en APIs ocultas (Blind Fuzzing) e inyectar *Payloads* destructivos sobre cuerpos POST y JSON de Single Page Applications (SPAs). Detecta inyecciones invisibles como **SQLi Ciega (Time-Based)** y **DOM-Based XSS** mediante el motor de renderizado. Complementado con análisis estático (SAST) de fugas de secretos JS.
- **Reportes Enriquecidos**: Generación automática de reportes en JSON y Markdown, incluyendo severidades CVE.
- **Suite de Tests (QA)**: 101 pruebas unitarias asíncronas y de integración. Código fuente validado 100% libre de errores estáticos (Flake8 Zero-Defects).

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

# Instalar dependencias principales
pip install -r requirements.txt

# [Atención Windows/macOS] Instalación de Motor Playwright:
# Si ejecutas el escáner desde Kali Linux, el núcleo se anclará al 
# binario nativo del OS (/usr/bin/chromium) ahorrando descargas cruzadas.
# Sin embargo, si lo ejecutas desde Windows o MacOS, debes empotrar el
# Chromium aislado de Playwright ejecutando obligatoriamente:
playwright install chromium
```

> **Dependencias principales**: `aiohttp`, `playwright`, `beautifulsoup4`, `aiohttp-socks`, `playwright-stealth`  

## 💻 Uso

### Interfaz de Línea de Comandos (CLI)

```bash
# Auditar un objetivo limitando simultaneidad para evitar ban, ejecutando Stealth:
python run_scanner.py --url https://ejemplo.com --workers 50
```

Opciones disponibles:

- `--url`: URL objetivo (requerido).
- `--checks`: Lista de chequeos específicos (ej: `xss sqli`). Por defecto ejecuta todos.
- `--auth-jwt`: Inyectar token JWT estático para Stateful Scanning en APIs y SPAs.
- `--auth-cookie`: Inyectar Cabecera de Cookie cruda para ataques autenticados.
- `--max-pages`: Límite de páginas a crawlear (default: 50).
- `--workers`: Número de hilos/conexiones concurrentes (default: 20).
- `--report`: Nombre del archivo de reporte (default: `report.json`).

### 🕶️ Configuración de Proxies (Auto-Evación y Curación)
Para impedir baneos de IP por volumen L7, el motor soporta redes proxy SOCKS4/5/HTTP. Simplemente crea un archivo **`proxies.txt`** en la raíz del proyecto. El motor lo detectará automáticamente y ejecutará una rotación biológica (expulsando el proxy de la cola si el WAF arroja 403 o 429):
```text
# proxies.txt (Un proxy por línea, formato ip:puerto)
192.168.10.50:8080
10.0.1.15:1080
```

### 📋 Ayuda y Comandos

| Argumento           | Descripción                                                   | Requerido |    Default    |
| :------------------ | :------------------------------------------------------------ | :-------: | :-----------: |
| `-h`, `--help`      | Muestra el mensaje de ayuda y termina.                        |    No     |       -       |
| `--url URL`         | URL objetivo para iniciar el escaneo.                         |  **Sí**   |       -       |
| `--checks [CHECKS]` | Lista de chequeos específicos a ejecutar (ej: `xss`, `sqli`). |    No     |     `all`     |
| `--max-pages N`     | Número máximo de páginas a visitar durante el crawling.       |    No     |     `50`      |
| `--workers N`       | Número de hilos/conexiones concurrentes.                      |    No     |     `20`      |
| `--report FILE`     | Nombre y ruta del archivo de reporte a generar.               |    No     | `report.json` |
| `--auth-jwt TOKEN`  | Token JWT estático puro para escaneo con estado persistente.  |    No     |       -       |
| `--auth-cookie C`   | Volcado en crudo del encabezado Cookie para inicio de sesión. |    No     |       -       |

## 🛡️ Capacidades de Detección

La versión actual incluye los siguientes plugins integrados:

1. **Reflected XSS**: Detección de Cross-Site Scripting reflejado mediante inyección y parseo.
2. **DOM-Based XSS**: Escaneo dinámico interceptando diálogos JS mediante navegadores Playwright Fantasmas (NUEVO).
3. **SQL Injection (Error-Based)**: Inyección y fuga SQL basada en errores base.
4. **Blind SQL Injection (Time-Based)**: Detección asíncrona ciega mediante cálculo matemático de latencias sobre Sleep Payloads (NUEVO).
5. **Secrets Leak**: Búsqueda SAST de claves de AWS (`AKIA*`), Tokens, PEM privadas.
6. **Security Headers**: Auditoría analítica de cabeceras de respuesta (HSTS, CSP).
7. **Sensitive Files**: Descubrimiento de puntos expuestos. Combate falsos Soft 404s en implementaciones SPA.
8. **CSRF**: Inyección y evasión paralela de tokens *authenticity*.
9. **SSRF Candidates**: Forja de peticiones a nivel del lado del servidor.

## 📈 Tubería de Ejecución y Ecosistema (Core Engine V2)

En la versión más reciente, el orquestador (`engine.py`) ha sido profundamente rediseñado para acoplar nativamente 5 utilidades arquitectónicas de grado Enterprise. A continuación, el detalle del ciclo de vida interno de escaneo:

1. **Doble Escudo Heurístico (Soft404Profiler + SensitiveFileValidator)**: Antes de despachar el enjambre de hilos asíncronos en el `crawl_loop`, el motor ejecuta una calibración síncrona enviada a un sub-hilo independiente (`asyncio.to_thread`) para perfilar cómo responde el objetivo a archivos inexistentes. **Silenciamiento Exhaustivo**: El módulo enmudece limpiamente en el núcleo dependencias base colisionadas u obsoletas pre-cargadas en Sistemas Operativos ofensivos (ej. *urllib3 RequestsDependencyWarning* habituales de Kali Linux), conservando el output inmaculado para el operador. Extrae Hashes MD5 y longitudes DOM dinámicas. Luego, durante la ejecución asíncrona, cualquier hallazgo `200 OK` pasa primero por un Validador Heurístico de Capa 7 (`SensitiveFileValidator`) que rastrea firmas inyectables de React/Vue (`<div id="root">`) cruzando lógicas estrictas por extensión de archivo (ej. exigiendo sentencias `INSERT INTO` para validar volcados `.sql`). Esto asegura que el subsistema jamás reporte falsos ".env" o "config.php" engañosos provistos por WAFs o balanceadores traicioneros.
2. **Intercepción de Transporte (`StealthManager`)**: El escáner ya no invoca peticiones de forma descubierta. En la etapa de Fetch, el núcleo inyecta la función `async_request` en un *wrapper* de protección ofensiva. Ésta envuelve el tráfico asíncrono aplicando retardos estocásticos de simulación humana (Jitter), rotando IPs mediante un pool dinámico de Proxies (`proxies.txt`), falsificando cabeceras de red interna (`X-Forwarded-For: 127.0.0.1`), e implementando semáforos de BackOff automático. Además, mediante heurística pasiva, si intercepta un bloqueo antibots (ej. **403 Cloudflare/Datadog**), aplica un cerrojo condicional (*Thread-Safe Lock*) sobre el enjambre concurrente para aplacar bucles masivos de renderizado, y deriva la resolución asincrónica 1 sola vez al renderizador oculto para extraer y asimilar la cookie (`cf_clearance`).
3. **Persistencia Dinámica y Escaneo con Estado (Stateful Scanner)**: Permite inyección de sesión nativa vía CLI (`--auth-jwt`, `--auth-cookie`) garantizando que el Crawler nazca autenticado para auditar flujos privados (Carritos, Perfiles). Adicionalmente, el motor inyecta automáticamente variables CSRF detectadas al vuelo en nuevas peticiones. **Soporte Nativo para SPAs y APIs**: Si el analizador no detecta un CSRF tradicional, el gestor activa un algoritmo asumiendo validación por JWT. Si a mitad del ciclo del escaneo el cortafuegos expira el certificado, el sistema pausa los hilos transitoriamente, ejecuta asíncronamente un Auto-Login en background y reanuda el ataque sin perder progreso ni colgar el pool de conexiones.
4. **Extracción en SPAs In-flight (`DynamicRenderer`)**: El analizador detecta y reanima asíncronamente a Chromium `Playwright`. Para sortear barreras anti-bot extremas (Datadog, Cloudflare Turnstile), inyecta la librería *stealth* anulando las marcas automatizadas de WebDriver. **Bypass de Entorno (Kali Linux Nativo)**: Se engancha a ejecutables nativos `/usr/bin/chromium` si detecta la distribución ofensiva, inyectando mecánicas de desvío de Sandboxing (`--no-sandbox`) permitiendo su ejecución nativa e ininterrumpida bajo el superusuario `root`. Si falta la dependencia *Playwright*, se degrada elegantemente a un análisis DOM estático puro.
5. **Araña DAST Profunda (POST/Form Payload Dispatcher)**: El escáner ya no se limita a probar parámetros GET superficiales. El motor central intercepta y destripa el HTML buscando etiquetas `<form>`, recolectando mecánicamente sus campos (`<input>`, `<select>`), rutas (`action`) y método HTTP. Si una API SPA oculta sus parámetros, el escáner se acopla a una heurística de **Adivinación de Parámetros a Ciegas**, inyectando automáticamente campos tentativos (`q`, `id`, `email`). Finalmente, dispara diccionarios mutantes asíncronos hacia Interfaces de Tests Avanzadas (`sqli_blind.py`, `xss.py`) preparadas para la intercepción de ejecuciones en el DOM y retrasos temporales de bases de datos.
6. **Resolución Ofensiva CTI (`ThreatIntelEnricher`)**: Una vez colapsada la cola de escaneo activo (`queue.empty()`), el Engine extrajo pasivamente en las cabeceras `Server` una lista masiva de tecnologías. Se traspasa en Fase Final al Enriquecedor, el cual de forma totalmente asíncrona pero limitada por un Semáforo anti-rate limit, cruza la data local con APIs de Amenazas, deduplicando redundancias idénticas al milisegundo con *in-flight locks* de memoria, y listando `CVEs` certificados directos al Reporte Final (JSON/Markdown).
7. **Gestión de Memoria y Graceful Shutdown (Zero-Leak)**: El ciclo vital del orquestador implementa integraciones *Lazy* rigurosas entre el conector `Engine` y el núcleo TCP multiplexor `Network`. Esto garantiza desestructuraciones automáticas puras (`__aexit__`), erradicando permanentemente el leak de sockets *"Unclosed client session"* de Aiohttp. Inclusive frente a *crashes* imprevistos, *timeouts* por WAF o interrupciones de teclado del Pentester, el sistema cerrará las válvulas lógicas y librará el 100% de la carga del búfer TCP al sistema operativo de forma limpia.

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
        +get_random_proxy()
    }
    class SessionManager {
        +load_raw_cookie()
        +set_jwt()
        +extract_csrf_token()
        +handle_auto_refresh()
    }
    class Network {
        +init_network()
        +async_request(chunked_evasion)
    }
    class DynamicRenderer {
        +render_dom(url)
        +solve_cloudflare_challenge(url)
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
    class WafEncoder {
        +apply_random_mutation()
        +double_url_encode()
        +sqli_tamper()
    }

    CLI --> Engine : Parse Argumentos e inyecta Config
    Engine --> SessionManager : Configura Headers y Autenticación Global
    Engine --> SensitiveFileValidator : Nivel 1 - Filtro Heurístico DOM
    Engine --> Soft404Profiler : Nivel 2 - Calibración Temprana MD5
    Engine --> StealthManager : Delega Peticiones Ofensivas al Interceptor
    StealthManager --> Network : Envuelve a la capa asyncio nativa  
    StealthManager ..> DynamicRenderer : Intercepta 403s y usa Solver Antibot
    Engine --> DynamicRenderer : Reanima DOM con Playwright Stealth
    Engine "1" *-- "*" BaseCheck : Carga Interfaces dinámicamente (Type Strategy)
    BaseCheck --> SessionManager : El Plugin asimila y detecta extractores
    BaseCheck ..> WafEncoder : Delega Mutación Polimórfica de Payloads
    Engine --> ThreatIntelEnricher : Intercambio de Data CTI en Post-Procesamiento (CVEs)
```

### Principios Fundamentales
1. **Separación de Responsabilidades (SoC):** El motor se abstrae completamente del ataque, concentrándose puramente en la encolación masiva en grafos. El módulo `Network` tampoco conoce al WAF, es envuelto quirúrgicamente por `StealthManager`.
2. **Abierto a Extensión:** Agniadir soporte para esquemas avanzados de reautenticación o interconectar APIs privadas propietarias sobre el `ThreatIntelEnricher` no demanda ninguna refactorización a `BaseCheck` ni obliga a romper la estabilidad inmensamente testeada (95/95 Unit Tests) de los middlewares centrales.

## ⚖️ Licencia

Este proyecto está licenciado bajo la **Licencia MIT**.

## ⚠️ DESCARGO DE RESPONSABILIDAD (DISCLAIMER)

Esta herramienta ha sido desarrollada **exclusivamente con fines educativos y de auditoría de seguridad autorizada**. WebVulnScanner ayuda a administradores y analistas a identificar fugas y errores operacionales propios. Su uso ilícito contra un patrimonio informático ajeno no autorizado penaliza severamente por la ley y **es responsabilidad unívoca del ejecutor directo**.
