# Roadmap: Estrategias Avanzadas de Evasión de WAF (Web Application Firewalls)

Este documento recopila las directrices y estrategias de ciberseguridad ofensiva planificadas para implementarse en el núcleo de **WebVulnScanner V2 Modular** a corto/mediano plazo, con el objetivo de lograr una evasión de grado militar contra WAFs modernos (Cloudflare, Imperva, AWS WAF, Akamai).

---

## 1. Rotación de Proxies Residenciales Dinámicos (IP Rotation)
El factor principal por el que los WAFs bloquean un escaneo es la volumetría anómala de peticiones originadas desde una única dirección IP.

- **Implementación Propuesta**: 
  - Integrar soporte para proxies empleando la librería `aiohttp-socks`.
  - Crear un módulo que lea un archivo `proxies.txt` y que el `StealthManager` rote la IP origen en modo *Round-Robin* o estocástico por cada petición. 
  - **Auto-Healing**: Si el WAF emite un código `403 Forbidden` repentino, la IP infractora se marcará como "quemada" y se eliminará del *pool* dinámicamente sin abortar el escaneo global.

## 2. Mutación y Ofuscación Polimórfica de Payloads
Los WAFs bloquean firmas conocidas utilizando Expresiones Regulares (ej. analizando `UNION SELECT` o `<script>alert`).

- **Implementación Propuesta**: 
  - Desarrollar un nuevo módulo dedicado (`webvulnscanner/utils/encoder.py`) que tome el Payload en crudo y lo altere matemáticamente antes de inyectarlo en la red:
    - **Double URL-Encoding**: Reemplazar `<script>` por `%253Cscript%253E`.
    - **SQLi Tampering**: Reemplazar espacios en blanco por comentarios SQL aleatorios (ej. `UNION/**/SELECT/**/1,2,3`).
    - **Unicode/Hex Encoding**: Bypassear normalizadores de WAF mediocres enviando el ataque codificado mientras el backend afectado falla y lo procesa en sucio.

## 3. Falsificación de Identidad por Cabeceras (Header Spoofing / IP Bypassing)
Muchos WAFs puentean (dejan pasar en lista blanca) o confían ciegamente en el tráfico que identifican como proveniente de la red interna o del propio localhost originario.

- **Implementación Propuesta**: 
  - En el `engine.py` o en el `SessionManager`, inyectar heurísticamente cabeceras falsificadas en cada *Request* asíncrona para manipular la visión geométrica del Firewall:
    - `X-Forwarded-For: 127.0.0.1`
    - `X-Originating-IP: 127.0.0.1`
    - `Client-IP: 127.0.0.1`
    - `X-Remote-IP: 127.0.0.1`

## 4. Fragmentación Acústica de Tráfico L7 (HTTP Chunked Transfer Bypassing)
Ciertos WAFs se quedan sin buffer de memoria o abortan prematuramente si intentan reensamblar y leer paquetes masivamente fragmentados a la hora de buscar firmas biométricas de ataque.

- **Implementación Propuesta**: 
  - Habilitar a nivel del `aiohttp` la opción de **Transfer-Encoding: chunked**. 
  - Enviar payloads ofensivos (ej. XSS) divididos asincrónicamente en minúsculos trozos de 1 byte. 
  - El WAF, por eficiencia, ignorará el paquete ensamblado, pero el servidor esclavo final (Nginx/Apache) de fondo lo reensamblará nativamente y detonará la red.

## 5. Inyección "Stealth" en Playwright (Evasión de Anti-Bots Turnstile/Datadog)
Actualmente, Playwright utiliza el motor binario estándar de Chromium de forma *"Headless"*. Plataformas como Cloudflare lo detectan en nanosegundos utilizando *fingerprinting* JavaScript avanzado (leyendo variables inalterables intrínsecas como `navigator.webdriver = true` o chequeando la firma gráfica del *Canvas*).

- **Implementación Propuesta**: 
  - Importar la librería especializada de camuflaje `playwright-stealth`. 
  - Modificar el módulo `browser.py` para cargarla e inyectarla en el `self.context.new_page()`.
  - Como resultado, el navegador reescribirá agresivamente todos sus atributos de huella dactilar, robando la identidad de un Google Chrome comercial 100% puro para escritorio impidiendo de facto el ser catalogado como araña.
