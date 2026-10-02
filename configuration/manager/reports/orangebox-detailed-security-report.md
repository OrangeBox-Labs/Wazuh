# OrangeBox Wazuh — Informe de Seguridad Detallado

Informe operativo que complementa el reporte ejecutivo. Muestra la actividad de seguridad por servidor y por grupo Wazuh.

## Qué hace

Presenta el detalle de cada servidor perteneciente a los grupos seleccionados, sin limitarse a un Top.

Por cada servidor muestra:

- estado e IP;
- eventos de seguridad;
- alertas de alta severidad;
- alertas críticas;
- detecciones clasificadas como ataque;
- IPs de origen observadas;
- distribución por categoría;
- principales detecciones;
- IPs bloqueadas por firewall-drop con su motivo;
- técnicas MITRE;
- CVE críticos del inventario;
- indicador especial para CloudLinux cuando Wazuh no entrega evaluación nativa de vulnerabilidades.

## Implementación actual

El archivo productivo es:

~~~~text
/var/ossec/reports/orangebox-detailed-security-report.py
~~~~

El script es autocontenido en ejecución. Lleva embebidos el motor compartido, la lógica necesaria del reporte ejecutivo y el renderer detallado. No importa los archivos Python productivos desde el sistema.

Comparte el mismo cache que el informe ejecutivo:

~~~~text
/var/ossec/reports/cache-proto-v3/
~~~~

Ese nombre se mantiene por compatibilidad con los datos ya construidos. Es el cache productivo actual, no un prototipo.

El script usa sys.dont_write_bytecode = True y no necesita que exista __pycache__.

## Flujo de ejecución

El flujo actual es:

~~~~text
período
  → grupos Wazuh
  → actualización del cache
  → lectura de shards de los servidores seleccionados
  → estadísticas por servidor
  → CVE / CloudLinux
  → HTML detallado
  → archivo
  → correo
~~~~

El motor compartido normaliza, clasifica y deduplica antes de guardar los eventos en cache.

## Cache compartido

La estructura actual es:

~~~~text
/var/ossec/reports/cache-proto-v3/
  YYYY-MM-DD/
    <agent-id>.jsonl.gz
    manifest.json
  YYYY-MM-DD.state.json
~~~~

### Día actual

alerts.json se procesa de manera incremental usando inode y offset.

Si no cambió desde la ejecución anterior, no se vuelve a leer desde el principio.

Si cambió el inode, se redujo de tamaño o la estructura del estado no es válida, el día se reconstruye.

### Días cerrados

Los históricos se convierten una vez a shards comprimidos por servidor.

Cada día tiene manifest.json y estado con metadatos de la fuente, eventos, servidores y tamaño.

Las reconstrucciones se hacen en un directorio temporal y luego se reemplazan de forma atómica.

### Lectura selectiva

El reporte resuelve primero los servidores de los grupos seleccionados y después lee únicamente sus shards.

Por eso un reporte de un cliente no necesita descomprimir el histórico de todos los servidores.

## Rendimiento validado

En una prueba con:

~~~~text
56 servidores
4.233.850 eventos
9.760 alertas de alta severidad
9 alertas críticas
10.839 detecciones de ataque
~~~~

la ejecución con cache construido registró:

~~~~text
Cache/update:     0,004 s
Lectura cache:    28,098 s
Agregación/CVE:    1,790 s
Render HTML:       0,908 s
Archivo:           0,013 s
Tiempo total:     40,058 s
~~~~

La primera construcción histórica tarda más porque crea el cache desde los logs originales.

En la prueba, el cache pasó de aproximadamente 188 MB con el esquema anterior a 49 MB con el esquema actual.

## Períodos

| Opción | Período |
|---|---|
| --today | Hoy desde 00:00 |
| --yesterday | Día calendario anterior completo |
| --thisweek | Semana actual desde lunes |
| --lastweek | Semana calendario anterior |
| --thismonth | Mes actual desde el día 1 |
| --lastmonth | Mes calendario anterior |
| --thisyear | Año actual desde el 1 de enero |
| --lastyear | Año calendario anterior |
| --date YYYY-MM-DD | Día indicado |

## Grupos

El parámetro --group acepta un grupo o varios grupos separados por coma.

La pertenencia de los servidores se resuelve directamente desde Wazuh mediante agent_groups.

No existe una lista manual de agentes que haya que actualizar al incorporar un servidor.

Con:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group CTS,OLC --email <destinatario>
~~~~

se incluyen los servidores pertenecientes a ambos grupos.

Con --group all se resuelven los grupos efectivos.

En el consolidado global se excluyen actualmente los grupos técnicos:

~~~~text
default
cpanel
zimbra
~~~~

Estos grupos pueden solicitarse explícitamente cuando corresponda.

La lista está controlada por REPORT_NON_CLIENT_GROUPS en el script. Si aparece un nuevo grupo técnico que no representa clientes, debe agregarse allí antes de usar --group all en producción.

Un servidor que pertenezca a más de un grupo aparece en cada grupo correspondiente, pero se reutilizan sus estadísticas sin volver a leer los logs.

## Contenido por servidor

### Resumen

Cada servidor informa:

- nombre e ID;
- estado;
- IP;
- eventos;
- alta severidad;
- críticas;
- ataques;
- cantidad de IPs de origen;
- cantidad de IPs bloqueadas.

### Principales detecciones

Se muestran las detecciones principales por nombre y descripción normalizados.

No se muestran los IDs de regla como elemento principal del informe.

### Firewall-drop

Las IPs bloqueadas se muestran por servidor y con el motivo que originó el bloqueo.

La correlación conserva directamente el par:

~~~~text
(rule_id, description)
~~~~

Esto evita que un motivo de una regla termine asociado a otra regla.

Los intentos detectados corresponden a alertas Wazuh relacionadas con las IPs que fueron bloqueadas. No equivalen necesariamente al número bruto de conexiones originales.

### FIM

Los cambios de File Integrity Monitoring se resumen por ubicación y cantidad de rutas únicas para evitar llenar el correo con cientos de archivos.

### MITRE

Se muestran las técnicas observadas, su descripción y la cantidad de alertas Wazuh asociadas.

El contador representa alertas, no accesos exitosos ni compromisos confirmados.

## GeoIP

La geolocalización usa DB-IP City Lite desde:

~~~~text
/var/lib/orangebox/geoip/dbip-city-lite.mmdb
~~~~

La ruta puede cambiarse con ORANGEBOX_GEOIP_CITY_DB.

Las tablas de IP muestran país y bandera cuando existe información.

El detalle también incluye:

- Top países por IPs públicas únicas asociadas a eventos de seguridad;
- Top países por IPs públicas bloqueadas automáticamente.

Las IP privadas, reservadas o no globales se muestran como IP local y no se incluyen en los rankings.

La geolocalización es aproximada y sirve como contexto de seguridad.

Fuente: DB-IP Lite, licencia CC BY 4.0.

## Vulnerabilidades

Los CVE se consultan desde:

~~~~text
wazuh-states-vulnerabilities-*
~~~~

También se consulta:

~~~~text
wazuh-states-inventory-system-*
~~~~

Esto permite distinguir entre un servidor sin hallazgos y un servidor cuya evaluación de vulnerabilidades no está disponible.

### CloudLinux

Cuando un servidor es identificado como CloudLinux, el informe lo marca explícitamente.

Un resultado vacío de wazuh-states-vulnerabilities-* para ese servidor no debe interpretarse como ausencia de CVE, porque Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esa distribución.

Las credenciales del Indexer pueden venir de:

~~~~text
WAZUH_INDEXER_USER
WAZUH_INDEXER_PASS
~~~~

o de:

~~~~text
/var/ossec/etc/orangebox-indexer.conf
~~~~

El archivo debe tener permisos 0600 o más restrictivos.

## Correo

Se acepta uno o más destinatarios con --email.

La entrega usa:

~~~~text
/usr/sbin/sendmail -t -i
~~~~

El mensaje queda en la cola local de Postfix.

Los asuntos actuales son:

~~~~text
[ORANGEBOX] Diario - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Semanal - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Mensual - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Anual - Informe de Seguridad Detallado - <grupo>
~~~~

Con más de un grupo, el asunto se adapta al consolidado.

## Archivo HTML

Cada ejecución se guarda en:

~~~~text
/var/ossec/reports/archive/
~~~~

La escritura usa archivo temporal y reemplazo atómico.

El correo contiene HTML y una alternativa de texto plano.

## Uso

Diario:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group <grupo> --email <destinatario>
~~~~

Semanal:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --lastweek --group <grupo> --email <destinatario>
~~~~

Mensual:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --lastmonth --group <grupo> --email <destinatario>
~~~~

Todos los grupos:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group all --email <destinatario>
~~~~

Prueba sin enviar correo:

~~~~bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group <grupo> --email <destinatario> --dry-run
~~~~

El script permite también indicar otro directorio de cache con --cache-dir para pruebas controladas.

## Mantenimiento

No crear listas manuales de servidores.

No modificar la estructura del cache sin definir una reconstrucción compatible.

No borrar los logs JSON de Wazuh que todavía formen parte del período de retención.

El wrapper limpia temporales conocidos de cache y HTML.

Los prototipos usados durante la migración ya no forman parte de la operación productiva.