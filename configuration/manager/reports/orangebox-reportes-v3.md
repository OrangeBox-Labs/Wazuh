# OrangeBox Wazuh — Reportes v3

## Estado

El reporte ejecutivo y el reporte detallado v3 están homologados y validados en producción.

Archivos:

- `configuration/manager/reports/orangebox-security-report.py`
- `configuration/manager/reports/orangebox-detailed-security-report.py`

Los prototipos usados durante la migración dejan de formar parte del árbol productivo.

## Motivo del cambio

La versión anterior volvía a recorrer y parsear los históricos en cada ejecución. Con 56 servidores y 4.233.850 eventos de seguridad esto hacía que cada reporte pagara nuevamente el costo de lectura y parseo.

v3 separa el trabajo:

1. Wazuh se parsea y normaliza una sola vez.
2. El resultado queda en cache comprimido.
3. Los reportes leen solo los agentes necesarios y trabajan sobre el cache.

El objetivo principal no fue solo bajar segundos: fue evitar el reparseo completo del histórico en cada ejecución.

## Arquitectura

```text
alerts.json / ossec-alerts-YYYY-MM-DD.json.gz
                    |
                    v
              motor cache v3
                    |
        +-----------+-----------+
        |           |           |
   normaliza   clasifica   deduplica
        |           |           |
        +-----------+-----------+
                    |
                    v
/var/ossec/reports/cache-proto-v3/
  YYYY-MM-DD/
      <agent-id>.jsonl.gz
      manifest.json
  YYYY-MM-DD.state.json
```

El cache se comparte entre ambos reportes.

El nombre `cache-proto-v3` se conserva para no invalidar los datos ya construidos. El contenido es la implementación de producción v3.

## Cache incremental

### Día actual

Se conserva inode y offset de `/var/ossec/logs/alerts/alerts.json`.

Si el archivo no cambió, la siguiente ejecución continúa desde el último punto procesado. Si cambió inode, se redujo de tamaño o falta la estructura esperada, el día se reconstruye.

### Días cerrados

Los logs diarios se procesan una vez y se guardan por servidor.

Cada día conserva un `manifest.json` y un estado con fuente, tamaño, mtime, eventos, servidores y tamaño de cache.

Las reconstrucciones usan directorio temporal y reemplazo atómico. Una interrupción no convierte un cache incompleto en cache válido.

### Shards

v2 guardaba un archivo grande por día. v3 usa un shard `<agent-id>.jsonl.gz` por servidor.

Ventajas:

- un reporte de cliente puede leer solo sus agentes;
- menor trabajo de descompresión;
- mejor compresión por homogeneidad de datos;
- ambos reportes reutilizan el mismo contenido.

## Flujo de los reportes

### Ejecutivo

Período → grupos → cache → lectura de shards → agregación → CVE → HTML → archivo → correo.

### Detallado

Período → grupos → cache → lectura de shards → estadísticas por servidor → CVE/CloudLinux → HTML detallado → archivo → correo.

Ambos comparten parseo, clasificación, normalización, deduplicación y tratamiento de `firewall-drop`.

## Cambios funcionales importantes

### `--group all`

Ahora `all` se interpreta como alias y se expande a los grupos efectivos.

Nunca se muestra la etiqueta literal `all` en el reporte.

En el detallado, `default`, `cpanel` y `zimbra` se tratan como grupos técnicos y se excluyen del consolidado global. Siguen pudiendo solicitarse explícitamente.

La pertenencia de los agentes sigue viniendo de Wazuh. No hay una lista manual que mantener.

### Asuntos

Ejecutivo:

```text
[ORANGEBOX] Diario - Informe de Seguridad <grupos>
[ORANGEBOX] Semanal - Informe de Seguridad <grupos>
[ORANGEBOX] Mensual - Informe de Seguridad <grupos>
[ORANGEBOX] Anual - Informe de Seguridad <grupos>
```

Detallado:

```text
[ORANGEBOX] Diario - Informe de Seguridad Detallado <grupos>
[ORANGEBOX] Semanal - Informe de Seguridad Detallado <grupos>
[ORANGEBOX] Mensual - Informe de Seguridad Detallado <grupos>
[ORANGEBOX] Anual - Informe de Seguridad Detallado <grupos>
```

No se usan iconos en el asunto.

### IPs bloqueadas

El detallado antes mantenía reglas y motivos en contadores separados y luego los cruzaba. Esto podía mostrar un motivo asociado a la regla equivocada.

Ahora se conserva directamente:

```text
(rule_id, description) -> cantidad
```

Por eso una IP puede aparecer correctamente como:

```text
10025 — WEB: Posible fuerza bruta web.
10026 — WEB: Posible reconocimiento automatizado...
10457 — SYN FLOOD
```

## Rendimiento validado

Prueba de control:

- 56 servidores
- 4.233.850 eventos
- 9.760 alertas de alta severidad
- 9 alertas críticas
- 10.839 detecciones de ataque

Baseline anterior:

```text
Lectura cache:   29,805 s
Agregación/CVE:   1,713 s
Render HTML:      0,983 s
Tiempo total:    42,410 s
```

Primera ejecución v3:

```text
Cache/update:   373,809 s
Lectura cache:   26,581 s
Agregación/CVE:   1,714 s
Render HTML:      0,907 s
Tiempo total:   413,955 s
```

La primera ejecución incluye la construcción del cache histórico y por eso es excepcionalmente más lenta.

Ejecución v3 con cache construido:

```text
Cache/update:     0,004 s
Lectura cache:    28,098 s
Agregación/CVE:    1,790 s
Render HTML:       0,908 s
Archivo:           0,013 s
Tiempo total:     40,058 s
```

Comparado con el baseline:

- tiempo total: ~5,5 % menor;
- lectura: ~5,7 % menor;
- render: ~7,6 % menor;
- conteos: idénticos.

La lectura sigue siendo la parte dominante porque todavía hay que descomprimir y materializar millones de eventos.

## Tamaño

En la prueba observada:

```text
Cache v2: 188 MB
Cache v3:  49 MB
```

Reducción aproximada: **74 %**.

## Higiene

El wrapper limpia residuos de ejecuciones interrumpidas sin tocar datos válidos.

Se limpian solamente temporales conocidos: directorios temporales de reconstrucción, `.tmp`, `.partial`, `.part`, `.swp` y restos temporales de compresión.

Los HTML también se escriben mediante archivo temporal y reemplazo atómico.

## Validación

Se comprobó:

- conteos idénticos al baseline;
- ejecución con múltiples grupos;
- `--group all`;
- asunto normalizado;
- ejecutivo correcto;
- detallado correcto;
- reglas y motivos de firewall correctamente emparejados;
- cache compartido;
- limpieza de temporales;
- ejecución sin los prototipos.

## Operación

Ejecutivo:

```bash
/var/ossec/reports/orangebox-security-report.py --today --group all --email <destinatario>
```

Detallado:

```bash
/var/ossec/reports/orangebox-detailed-security-report.py --today --group all --email <destinatario>
```

Pruebas:

```bash
... --dry-run
```

HTML:

```text
/var/ossec/reports/archive/
```

Cache:

```text
/var/ossec/reports/cache-proto-v3/
```

## Mantenimiento

Los reportes son autocontenidos.

No crear listas manuales de agentes.

No cambiar el formato del cache sin subir su versión y definir una reconstrucción.

El motor embebido no debe editarse a mano sin volver a probar ambos reportes.

## Próxima etapa

v4 queda fuera de este cambio.

La evolución prevista es materializar eventos y agregados en una base de datos para que reportes, dashboard, API y monitoreo compartan la misma información sin tener que descomprimir millones de eventos en cada ejecución.
