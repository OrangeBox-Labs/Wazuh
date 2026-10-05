# OrangeBox Wazuh — Informe de Seguridad

Informe de actividad de seguridad generado por Wazuh. La implementación actual es productiva, autocontenida y genera en una sola ejecución el resumen ejecutivo y el reporte detallado.

## Qué hace

Genera informes diarios, semanales, mensuales y anuales, para uno o varios grupos Wazuh.

El informe resume la actividad de seguridad del período y muestra:

- eventos de seguridad;
- alertas de alta severidad;
- alertas críticas;
- IPs de origen observadas;
- servidores afectados;
- bloqueos automáticos de IPs;
- intentos de acceso y exploración web;
- cambios de archivos y actividad FIM;
- malware y archivos sospechosos;
- escalamiento de privilegios;
- detecciones clasificadas como intentos de ataque;
- técnicas MITRE observadas;
- servidores más afectados;
- vulnerabilidades críticas del inventario Wazuh.

El objetivo es entregar una vista ejecutiva sin perder la trazabilidad necesaria para investigar un evento.

## Implementación actual

El archivo productivo es:

~~~~text
/var/ossec/reports/orangebox-security-report.py
~~~~

El script es autocontenido:

- el motor de lectura y normalización está embebido;
- la lógica del reporte ejecutivo está embebida;
- no depende de importar otro script productivo desde el sistema;
- usa un único motor y un único cache para el resumen y el detallado;
- genera el resumen en el cuerpo del correo y el detallado como ZIP adjunto;
- usa sys.dont_write_bytecode = True para no generar __pycache__.

El directorio del cache se llama:

~~~~text
/var/ossec/reports/cache-proto-v3/
~~~~

El nombre se conserva por compatibilidad con los datos existentes. No corresponde a un prototipo ni a una implementación alternativa: es el cache productivo que usa actualmente el reporte.

## Fuentes de datos

Se leen las alertas JSON de Wazuh:

~~~~text
/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json
~~~~

Los históricos comprimidos se leen directamente con gzip.

Las acciones de firewall-drop se reconstruyen desde las alertas 10458. El payload de Active Response contiene la alerta original, la regla, el agente y la IP de origen que provocó el bloqueo.

No se usa active-responses.log como fuente histórica principal.

## Cache y rendimiento

El primer procesamiento de un día cerrado construye un cache comprimido por servidor. Las ejecuciones siguientes reutilizan ese cache y no vuelven a parsear todo el histórico.

La estructura es:

~~~~text
/var/ossec/reports/cache-proto-v3/
  YYYY-MM-DD/
    <agent-id>.jsonl.gz
    manifest.json
  YYYY-MM-DD.state.json
~~~~

### Día actual

Se conserva inode y offset de alerts.json.

Si el archivo no cambió, la siguiente ejecución continúa desde el último punto procesado. Si cambió el inode, disminuyó de tamaño o falta la estructura esperada, el día se reconstruye.

### Días cerrados

Cada día se procesa una vez y se guarda en shards por servidor.

Las reconstrucciones usan directorio temporal y reemplazo atómico. Un proceso interrumpido no convierte un cache incompleto en cache válido.

### Lectura selectiva

El reporte resuelve primero los agentes de los grupos pedidos y después lee solo los shards necesarios.

Esto permite que un informe de cliente no tenga que descomprimir los datos de todos los servidores.

### Prueba validada

En una prueba con:

~~~~text
56 servidores
4.233.850 eventos
9.760 alertas de alta severidad
9 alertas críticas
10.839 detecciones de ataque
~~~~

el resultado con cache construido fue:

~~~~text
Cache/update:     0,004 s
Lectura cache:    28,098 s
Agregación/CVE:    1,790 s
Render HTML:       0,908 s
Archivo:           0,013 s
Tiempo total:     40,058 s
~~~~

El baseline anterior fue 42,410 s con los mismos conteos.

La primera construcción histórica del cache fue mucho más lenta porque incluyó el procesamiento inicial de los logs. Eso es un costo de calentamiento, no el tiempo normal de ejecución.

En la misma prueba, el cache pasó de aproximadamente 188 MB a 49 MB.

La lectura de los shards sigue siendo la etapa dominante porque el informe todavía debe descomprimir y recorrer millones de eventos seleccionados.

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

## Grupos Wazuh

El parámetro --group acepta uno o varios grupos separados por coma.

La pertenencia de cada servidor se obtiene desde Wazuh usando agent_groups. No existe una lista manual de agentes que deba mantenerse en el script.

Con:

~~~~bash
/var/ossec/reports/orangebox-security-report.py --yesterday --group CLIENTE_02,CLIENTE_03 --email <destinatario>
~~~~

el reporte considera solo los servidores pertenecientes a esos grupos.

Con:

~~~~bash
--group all
~~~~

el script resuelve los grupos efectivos y genera el consolidado correspondiente. No muestra la etiqueta literal all como si fuera un grupo de cliente.

Los grupos sin servidores se omiten.

## Clasificación de eventos

La clasificación se basa en IDs y grupos de reglas Wazuh.

Las categorías principales son:

~~~~text
active_response
authentication
web
fim
malware
privilege
attack
~~~~

También existen reglas y grupos excluidos explícitamente para evitar ruido operacional o excepciones OrangeBox.

Las alertas de nivel 0 o menor no entran en el resumen.

Las detecciones de ataque incluyen grupos como attack, brute_force, reconnaissance, credential_discovery, sensitive_file y lateral_movement. Además, una alerta de nivel 12 o superior puede clasificarse como ataque cuando no quedó antes en otra categoría específica.

“Intento de ataque” describe una detección con características ofensivas; no significa que el sistema haya sido comprometido.

## Bloqueo automático de IPs

La sección de firewall correlaciona la regla que originó la detección con la acción de firewall-drop.

Para cada servidor y motivo se muestra:

- regla;
- motivo;
- intentos detectados asociados;
- cantidad de IPs bloqueadas.

La correlación mantiene juntos ID de regla y descripción. Esto evita cruzar un motivo con otra regla.

Los intentos detectados son alertas Wazuh asociadas a las IPs que fueron bloqueadas. No equivalen necesariamente a la cantidad bruta de conexiones o solicitudes originales.

Las IP individuales no se listan en el reporte ejecutivo para mantener el informe legible. El detalle queda en las alertas JSON y en el informe detallado.

## GeoIP

La geolocalización usa DB-IP City Lite desde:

~~~~text
/var/lib/orangebox/geoip/dbip-city-lite.mmdb
~~~~

La ruta puede cambiarse con ORANGEBOX_GEOIP_CITY_DB.

No se consulta una API externa por cada IP durante la ejecución.

El informe muestra:

- país y bandera en tablas con IP individual;
- Top países por IPs públicas únicas asociadas a detecciones;
- Top países por IPs públicas bloqueadas automáticamente.

Las IP privadas, reservadas o no globales se consideran IP local y no entran en los rankings geográficos.

La geolocalización es aproximada y se usa como contexto de seguridad, no como identificación física exacta.

Fuente: DB-IP Lite, licencia CC BY 4.0.

## Técnicas MITRE

Cuando Wazuh entrega información MITRE ATT&CK, el reporte muestra el identificador, nombre y una explicación corta para facilitar la lectura.

El contador representa cantidad de alertas Wazuh asociadas a la técnica durante el período. No representa necesariamente accesos exitosos, conexiones individuales ni compromisos confirmados.

Entre las técnicas contempladas por el catálogo local se encuentran T1110, T1021.004, T1078, T1190, T1595.002, T1083, T1552, T1059.004, T1105 y T1505.003.

Si llega una técnica sin explicación local, se conserva el ID y el nombre informado por Wazuh y se usa una explicación genérica.

## Vulnerabilidades

Los CVE se consultan desde:

~~~~text
wazuh-states-vulnerabilities-*
~~~~

Para distinguir entre “sin hallazgos” y “sin evaluación”, también se consulta:

~~~~text
wazuh-states-inventory-system-*
~~~~

Cuando un servidor es identificado como CloudLinux, el informe lo indica expresamente. Un resultado vacío de Vulnerability Detection para CloudLinux no debe interpretarse como ausencia de CVE.

Las credenciales de lectura del Indexer se toman de variables de entorno o de:

~~~~text
/var/ossec/etc/orangebox-indexer.conf
~~~~

El archivo de configuración debe tener permisos 0600 o más restrictivos. El password no se almacena dentro del repositorio.

## Correo

Cada ejecución envía un solo correo por destinatario: el informe ejecutivo queda en el cuerpo del mensaje y el informe detallado completo se adjunta como archivo ZIP.

El destinatario se entrega con --email y puede repetirse para enviar a más de una dirección.

El HTML y el texto plano se envían mediante:

~~~~text
/usr/sbin/sendmail -t -i
~~~~

Esto entrega el mensaje a la cola local de Postfix.

Los asuntos actuales siguen este formato:

~~~~text
[ORANGEBOX] Diario - Informe de Seguridad <grupos>
[ORANGEBOX] Semanal - Informe de Seguridad <grupos>
[ORANGEBOX] Mensual - Informe de Seguridad <grupos>
[ORANGEBOX] Anual - Informe de Seguridad <grupos>
~~~~

No se usan iconos en el asunto.

El idioma por defecto es español y --lang es|en permite cambiar títulos y etiquetas del reporte.

## HTML y archivo

El HTML ejecutivo queda en el cuerpo del correo y también se archiva. El HTML detallado se comprime dentro de un ZIP para el adjunto y el histórico. Esto evita enviar varios correos y reduce drásticamente el tamaño del mensaje.

Los HTML están diseñados para clientes de correo y móvil:

- tablas HTML;
- estilos críticos inline;
- sin flexbox, CSS Grid ni JavaScript;
- ancho aproximado de 640 px;
- contenido adaptable a pantallas pequeñas.

Cada ejecución se archiva en:

~~~~text
/var/ossec/reports/archive/
~~~~

La escritura del HTML usa archivo temporal y reemplazo atómico para evitar archivos incompletos.

## Prueba

Para generar el informe sin enviarlo:

~~~~bash
/var/ossec/reports/orangebox-security-report.py --yesterday --group all --email <destinatario> --dry-run
~~~~

El archivo HTML sigue quedando disponible en archive.

## Operación recomendada

Diario global:

~~~~cron
0 10 * * * root /var/ossec/reports/orangebox-security-report.py --yesterday --group all --email <destinatario>
~~~~

Mensual global:

~~~~cron
0 10 1 * * root /var/ossec/reports/orangebox-security-report.py --lastmonth --group all --email <destinatario>
~~~~

Mensual de cliente:

~~~~cron
0 10 1 * * root /var/ossec/reports/orangebox-security-report.py --lastmonth --group <grupo_cliente> --email <destinatario>
~~~~

Agregar o retirar un cliente consiste en agregar o quitar su línea de cron.

## Mantenimiento

No crear listas manuales de servidores dentro del script.

No borrar alerts.json ni los históricos mientras exista una política de retención que los necesite.

No cambiar la estructura del cache sin definir primero una reconstrucción compatible.

El wrapper limpia solo residuos temporales conocidos de ejecuciones interrumpidas.

Los prototipos de la migración ya no forman parte de la instalación productiva.