# Implementaciones Futuras (Escáner de Red)

Con la arquitectura asíncrona actual (`AsyncNetworkScanner`), tenemos una base excelente para expandir la herramienta. Al poder abrir conexiones directas por TCP (sockets) de manera rápida y masiva, las posibilidades son enormes.

A continuación se detallan las grandes categorías sugeridas para futuros plugins de red:

### 1. Detección de Bases de Datos Expuestas
A menudo los desarrolladores olvidan configurar la autenticación o dejan expuestas las bases de datos al internet público. 
*   **Redis Abierto (Puerto 6379):** Conectarse por socket y enviar el comando `INFO`. Si devuelve datos sin pedir contraseña, la instancia es completamente vulnerable.
*   **MongoDB (Puerto 27017):** Verificar si la interfaz administrativa acepta conexiones no autenticadas.
*   **MySQL / PostgreSQL (Puertos 3306 / 5432):** Intentar autenticarse con el usuario por defecto (ej. `root` sin contraseña, `postgres:postgres`) o extraer la versión exacta de la base de datos (fuga de información/Threat Intel).

### 2. Protocolos de Administración Inseguros
*   **Telnet (Puerto 23):** Un plugin que detecte si el puerto está abierto y logre extraer el *banner* de bienvenida. Se debe reportar como severidad Alta o Crítica solo por usar protocolos en texto claro (Cleartext).
*   **SSH (Puerto 22):** 
    *   *Detección de algoritmos:* Extraer el *banner* para saber si están usando versiones antiguas y vulnerables de OpenSSH.
    *   *Fuerza Bruta Ligera:* Probar combinaciones obvias como `root:root`, `admin:admin` o probar si permite inicios de sesión sin contraseña.
*   **RDP / Escritorio Remoto (Puerto 3389):** Identificar si el servidor carece de NLA (Autenticación a nivel de red) o si es vulnerable a fallos conocidos (como *BlueKeep*), enviando el paquete inicial de negociación RDP.

### 3. Enumeración de Archivos y Recursos Compartidos
*   **SMB / CIFS (Puertos 139, 445):** 
    *   *Null Sessions:* Intentar listar los recursos compartidos enviando una sesión anónima (Null Session). Muy común en entornos Windows mal configurados o servidores NAS antiguos.
    *   *Vulnerabilidades Críticas:* Crear un escáner ligero que envíe el paquete inicial para ver si es vulnerable a *EternalBlue (MS17-010)*.
*   **NFS (Puerto 2049):** Consultar el *portmapper* para ver si exportan sistemas de archivos a cualquier IP visitante.

### 4. Detección de Fugas de Información Estructural (Infraestructura)
*   **DNS Zone Transfer (Puerto 53 TCP):** Un plugin que intente realizar una petición `AXFR` al servidor DNS. Si está mal configurado, expondrá un mapa completo de todos los subdominios de la empresa.
*   **Memcached (Puerto 11211):** Similar a Redis, enviar un comando de `stats` para ver si la memoria caché corporativa está totalmente expuesta a inyección/extracción de datos por no tener firewall.

---
**Nota de Implementación:** Cualquiera de estos plugins seguirá el mismo formato que el módulo FTP implementado. Heredarán de `BaseNetworkPlugin`, definirán la función asíncrona `check_service(self, ip, port)` y utilizarán un `asyncio.open_connection()` para hablar en crudo (bytes) con el protocolo.
