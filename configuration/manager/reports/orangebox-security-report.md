# orangebox-security-report.py

Motor de reportes **OrangeBox Wazuh Security Activity Report**.

El script genera reportes diarios, semanales, mensuales y anuales, globales o filtrados por grupo Wazuh.

Este es el **reporte ejecutivo**. El repositorio también incluye el **Informe de Seguridad Detallado** en `orangebox-detailed-security-report.py`, que presenta el desglose por agente y grupo Wazuh. Su documentación se encuentra en `orangebox-detailed-security-report.md`.

## Fuente de datos

El script utiliza los logs JSON de alertas de Wazuh:

```text
/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json
```

Los históricos `.json.gz` se leen directamente con `gzip`, sin descomprimirlos a disco.

No se utiliza `active-responses.log` como fuente histórica principal. Las ejecuciones de `firewall-drop` se reconstruyen desde las alertas `651`, cuyo `full_log` contiene el JSON de Active Response.

## Períodos

| Opción | Período |
|---|---|
| `--today` | Hoy 00:00 hasta el momento de ejecución |
| `--yesterday` | Día calendario anterior completo |
| `--thisweek` | Lunes 00:00 hasta el momento de ejecución |
| `--lastweek` | Semana calendario anterior completa |
| `--thismonth` | Día 1 del mes hasta el momento de ejecución |
| `--lastmonth` | Mes calendario anterior completo |
| `--thisyear` | 1 de enero hasta el momento de ejecución |
| `--lastyear` | Año calendario anterior completo |
| `--date YYYY-MM-DD` | Día específico completo |

## Grupos Wazuh

El filtro `--group` utiliza la pertenencia real de los agentes a grupos Wazuh mediante:

```text
/var/ossec/bin/agent_groups -l -g <grupo>
```

`all` incluye todos los agentes. Un grupo específico incluye únicamente los agentes que Wazuh reporta como miembros de ese grupo.

## Envío e idioma

El destinatario se entrega explícitamente con `--email` y es obligatorio.

El idioma por defecto es español. `--lang es|en` permite cambiar el idioma de títulos y etiquetas; las descripciones técnicas de Wazuh se conservan.

```bash
orangebox-security-report.py --yesterday --group all --email <destinatario>
orangebox-security-report.py --lastmonth --group <grupo_cliente> --email <destinatario>
orangebox-security-report.py --thismonth --group <grupo_cliente> --email <destinatario> --lang es
orangebox-security-report.py --lastyear --group all --email <destinatario> --lang en
```

El correo se entrega mediante la cola local de Postfix usando `/usr/sbin/sendmail -t -i`. Esto permite que el reporte quede en la cola aunque Postfix esté detenido temporalmente y sea entregado cuando el servicio vuelva.

```text
From: Wazuh SOC <TU_EMAIL>
```

El HTML generado se archiva bajo:

```text
/var/ossec/reports/archive/
```

## Diseño para correo electrónico

El renderer está diseñado específicamente para clientes de correo y utiliza:

- layout basado en tablas HTML;
- estilos críticos inline;
- sin `flex`, CSS Grid ni JavaScript;
- ancho máximo aproximado de 640 px;
- contenido adaptable a pantallas pequeñas;
- logo corporativo usado por las alertas OrangeBox;
- sin listas interactivas de IPs, para mantener una visualización consistente en Gmail, Carbonio, Thunderbird y móvil.

## Vulnerabilidades / CVE

El informe consulta los hallazgos críticos desde:

```text
wazuh-states-vulnerabilities-*
```

Para distinguir correctamente entre un agente sin hallazgos CVE y un agente que no está siendo evaluado por Vulnerability Detection, el reporte consulta además el inventario de sistema:

```text
wazuh-states-inventory-system-*
```

Cuando un agente es identificado como **CloudLinux**, el informe no presenta el estado como `0 CVE`. Muestra explícitamente que Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esa distribución y que el resultado **no debe interpretarse como ausencia de CVE**.

Esta distinción es importante porque el inventario de paquetes puede estar funcionando correctamente aunque no existan documentos de Vulnerability Detection para ese agente.

## Contenido del informe

El orden del informe está pensado para comenzar con una visión ejecutiva y terminar con información técnica.

### Resumen

Presenta:

- eventos de seguridad;
- alertas de alta severidad;
- IPs de origen observadas;
- sistemas afectados.

### Respuesta automática · Firewall Drop

Esta sección correlaciona las detecciones que originaron `firewall-drop` con las IPs que fueron bloqueadas.

Para cada sistema y regla muestra:

- motivo de la detección;
- regla Wazuh que originó el bloqueo;
- cantidad de intentos/detecciones correlacionados con las IP bloqueadas;
- cantidad de IPs bloqueadas automáticamente.

No se muestran las IP individuales en el correo. El detalle completo permanece disponible en las alertas JSON de Wazuh y en los datos históricos utilizados por el reporte.

Tampoco se muestra la duración configurada en Active Response porque describe la configuración del mecanismo, no la actividad observada. Ni se muestra la cantidad de ejecuciones `add` como métrica principal, porque varias ejecuciones pueden corresponder a una misma IP.

La correlación utiliza el mismo agente, regla e IP de origen. El contador de **intentos detectados** corresponde a detecciones Wazuh asociadas a las IP que fueron bloqueadas; no equivale necesariamente a la cantidad bruta de conexiones o solicitudes originales. Esto es especialmente importante en reglas de correlación por frecuencia, donde una alerta puede representar múltiples eventos de origen.

### Intentos de acceso

Resume autenticación, SSH, fuerza bruta y otras detecciones relacionadas con acceso.

### Intentos de acceso y exploración web

Resume reconocimiento y solicitudes HTTP asociadas a actividad sospechosa o intentos de acceso no autorizado.

### Cambios detectados en archivos

Resume actividad de File Integrity Monitoring y cambios relevantes detectados por Wazuh.

### Detecciones de malware y archivos sospechosos

Incluye reglas OrangeBox asociadas a malware, webshells y ejecutables sospechosos.

### Escalamiento de privilegios

Incluye reglas de `sudo`, `su` y elevación a root, incluyendo la detección OrangeBox `10005`.

### Detecciones clasificadas como intentos de ataque

Agrupa detecciones asociadas a grupos como:

```text
attack
brute_force
reconnaissance
credential_discovery
sensitive_file
lateral_movement
```

Además, la clasificación actual considera como actividad de ataque las alertas de severidad 12 o superior que no hayan quedado clasificadas antes en otra categoría específica.

El término **intento de ataque** se utiliza para destacar que la actividad presenta características compatibles con una acción ofensiva, sin afirmar que el atacante haya conseguido comprometer el sistema.

Esta sección es independiente del resumen MITRE. Por eso puede existir un informe donde esta sección indique que no hubo detecciones clasificadas como ataque y, al mismo tiempo, existan técnicas MITRE asociadas a otras alertas de autenticación, web, FIM o privilegios.

### Técnicas MITRE observadas en las alertas

Wazuh incorpora en las alertas los identificadores MITRE ATT&CK, junto con el nombre de la técnica y la táctica cuando están disponibles. El informe conserva el identificador técnico y añade una explicación corta pensada para personas no especialistas.

El contador de esta tabla indica **cuántas alertas de Wazuh fueron asociadas a la técnica** durante el período. No significa necesariamente la cantidad de accesos exitosos, conexiones individuales, ataques confirmados ni compromisos.

Por ejemplo, si aparece:

```text
T1021.004   SSH   Acceso remoto a sistemas mediante SSH.   54,914
```

el `54,914` debe interpretarse como **54,914 alertas de Wazuh asociadas a la técnica T1021.004**, no como 54,914 ingresos exitosos por SSH.

Las explicaciones se mantienen dentro del propio script para que el reporte sea portable y no dependa de una consulta externa durante su ejecución.

Actualmente se incluyen explicaciones para las técnicas observadas en los reportes OrangeBox, entre ellas:

```text
T1110       Fuerza bruta
T1110.001   Password Guessing
T1021       Remote Services
T1021.004   SSH
T1078       Valid Accounts
T1565.001   Stored Data Manipulation
T1070.004   File Deletion
T1485       Data Destruction
T1548.003   Sudo and Sudo Caching
T1055       Process Injection
T1190       Exploit Public-Facing Application
T1498       Network Denial of Service
T1595.002   Vulnerability Scanning
T1083       File and Directory Discovery
T1552       Unsecured Credentials
T1098       Account Manipulation
T1059       Command and Scripting Interpreter
T1059.004   Unix Shell
T1105       Ingress Tool Transfer
T1505.003   Web Shell
```

Si Wazuh incorpora una técnica que no tenga una explicación local, el script muestra igualmente el ID y el nombre proporcionados por Wazuh y utiliza una explicación genérica, evitando dejar un número sin contexto.

### Sistemas más afectados

Muestra los sistemas con mayor cantidad de detecciones relevantes durante el período.

## Qué se considera evento de seguridad

El motor clasifica las alertas mediante sus IDs y grupos Wazuh. Los eventos que no pertenecen a una categoría de seguridad conocida se mantienen fuera del resumen principal para evitar que el ruido operacional domine el informe.

Las categorías consideradas son:

```text
active_response
authentication
web
fim
malware
privilege
attack
```

Los eventos de prueba controlada OrangeBox se mantienen dentro de los reportes. Esto permite demostrar que las reglas y mecanismos de respuesta han sido probados y que las cifras observadas no son números generados artificialmente.

## Cron recomendado

Reporte diario global a las 10:00:

```cron
0 10 * * * root /var/ossec/reports/orangebox-security-report.py --yesterday --group all --email <destinatario>
```

Reporte mensual global el día 1 a las 10:00:

```cron
0 10 1 * * root /var/ossec/reports/orangebox-security-report.py --lastmonth --group all --email <destinatario>
```

Reporte mensual de un cliente:

```cron
0 10 1 * * root /var/ossec/reports/orangebox-security-report.py --lastmonth --group <grupo_cliente> --email <destinatario>
```

Agregar o retirar un reporte de cliente consiste únicamente en agregar o eliminar una línea de cron.

## Seguridad y aislamiento por cliente

El correo del cliente no se define dentro del código. Cron entrega el destinatario y el grupo en cada ejecución.

Por ejemplo:

```bash
--group <grupo_cliente> --email <destinatario>
```

contendrá exclusivamente agentes que Wazuh identifica como pertenecientes al grupo indicado.

No se deben utilizar listas manuales de agentes dentro del script para reemplazar la pertenencia oficial a grupos Wazuh.
