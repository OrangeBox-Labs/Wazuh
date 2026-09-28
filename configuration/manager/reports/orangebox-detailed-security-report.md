# OrangeBox Wazuh — Informe de Seguridad Detallado

Reporte operativo detallado, complementario al reporte ejecutivo `orangebox-security-report.py`. El reporte presenta el detalle por agente y grupo Wazuh.

## Identidad del informe

Este reporte corresponde al **Informe de Seguridad Detallado** de OrangeBox. El asunto del correo se genera dinámicamente según el período:

```text
[ORANGEBOX] Diario - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Semanal - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Mensual - Informe de Seguridad Detallado - <grupo>
[ORANGEBOX] Anual - Informe de Seguridad Detallado - <grupo>
```

El reporte ejecutivo y este informe detallado son informes complementarios: el ejecutivo resume la actividad global, mientras que el detallado desglosa la información por agente.

## Objetivo

Mostrar al cliente el detalle de seguridad de **cada agente perteneciente al grupo Wazuh**, sin limitarse a un Top 15.

Por cada agente se informa:

- Estado e IP del agente.
- Cantidad total de eventos de seguridad del período.
- Alertas de alta severidad (niveles Wazuh 12-14).
- Alertas críticas (niveles 15-16).
- Detecciones clasificadas como ataque.
- IPs de origen únicas observadas.
- Distribución de detecciones por categoría.
- Principales detecciones por nombre/descripción, sin mostrar IDs de regla.
- IPs bloqueadas por `firewall-drop`, con el motivo de bloqueo.
- Técnicas MITRE observadas.
- CVE críticos activos del inventario de vulnerabilidades.

Wazuh clasifica las reglas entre los niveles 0 y 16; los niveles 12-14 corresponden a eventos de alta importancia y los niveles 15-16 a severidad severa/máxima. citeturn251854search0

## Datos de vulnerabilidades

Los CVE se consultan directamente desde el índice de estado:

`wazuh-states-vulnerabilities-*`

Wazuh documenta este índice como la fuente de datos de vulnerabilidades actuales de los endpoints y expone campos como CVE, severidad, descripción, paquete, score y estado.

### CloudLinux

Para evitar presentar un resultado vacío como si fuera una evaluación completa, el reporte consulta además:

`wazuh-states-inventory-system-*`

Cuando el agente es identificado como **CloudLinux**, el detalle por agente indica explícitamente que Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esa distribución. Por lo tanto, un listado vacío de `wazuh-states-vulnerabilities-*` para ese agente **no debe interpretarse como ausencia de CVE**.

El inventario de paquetes del agente puede seguir siendo correcto y completo aunque Vulnerability Detection no genere estados de vulnerabilidad para CloudLinux. citeturn274081search0turn469205view0

El script requiere credenciales de lectura del Wazuh indexer. Se pueden entregar mediante:

`WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASS`

o mediante:

`/var/ossec/etc/orangebox-indexer.conf`

con permisos 0600:

```ini
WAZUH_INDEXER_USER=readall
WAZUH_INDEXER_PASS=xxxxxxxx
```

La instalación estándar de Wazuh guarda las credenciales del indexer del manager en su keystore; el reporte no intenta extraer secretos desde ese almacén. citeturn163425search1turn163425search2

## Uso

Diario:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group CLIENTE --email TU_EMAIL
```

Semanal:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --lastweek --group CLIENTE --email TU_EMAIL
```

Mensual:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --lastmonth --group CLIENTE --email TU_EMAIL
```

Todos los grupos:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group all --email TU_EMAIL
```

Prueba sin enviar correo:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group CLIENTE --email TU_EMAIL --dry-run
```

## Fuente de eventos

El reporte reutiliza `orangebox-security-report.py` para:

- selección de período;
- pertenencia a grupos;
- lectura de logs históricos comprimidos;
- parseo de alertas;
- clasificación de categorías;
- reconstrucción de `firewall-drop` desde las alertas 651.

Esto mantiene ambos reportes alineados en cuanto a qué se considera una detección.

Los logs de alertas son la fuente habitual de los eventos generados por Wazuh. citeturn251854search5

## Entrega de correo

El reporte usa `/usr/sbin/sendmail -t -i` para entregar el mensaje a la cola local de Postfix. Así, una detención temporal de Postfix no elimina el reporte: el mensaje queda encolado y se entrega cuando el servicio vuelve.

## Archivo HTML

Cada ejecución se archiva en:

`/var/ossec/reports/archive/`

El correo incluye una versión HTML y una alternativa de texto plano.


## Grupos de clientes vs. grupos funcionales

Los grupos Wazuh cumplen más de una función en esta instalación. Un grupo puede identificar a un cliente o describir una capacidad técnica compartida por varios endpoints.

Los reportes de cliente utilizan directamente el grupo indicado con `--group`. Por lo tanto, un grupo funcional como `cpanel` o `zimbra` no se convierte automáticamente en cliente ni recibe un correo por el solo hecho de existir.

Cuando se usa `--group all`, el reporte detallado excluye actualmente:

- `default`
- `cpanel`
- `zimbra`

Estos grupos siguen pudiendo consultarse explícitamente para reportes operacionales internos.

Cuando se cree un nuevo grupo funcional, debe agregarse a `REPORT_NON_CLIENT_GROUPS` en `orangebox-detailed-security-report.py` antes de considerarlo parte de la operación productiva. Esto evita que un grupo técnico aparezca accidentalmente como una sección de cliente en el reporte global.
