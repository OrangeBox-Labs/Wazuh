# Cron del Wazuh Manager

Las tareas programadas de OrangeBox se mantienen en `/etc/cron.d/` en lugar de concentrarse en el `crontab` personal de `root`.

El objetivo es que cada función tenga un archivo independiente, fácil de revisar, desplegar y retirar.

## Organización

### Tareas de sistema

Estas tareas mantienen listas o datos que consume el Manager:

- `orangebox-cpanel-agents` — genera dinámicamente la CDB de agentes que pertenecen al grupo Wazuh `cpanel`. Se usa para excepciones operacionales de WP Toolkit sin mantener una lista manual de agentes.
- `orangebox-backuppc` — ejemplo de actualización de una whitelist dinámica de BackupPC.
- `orangebox-geoip` — actualización periódica de bases/listas Geo-IP.
- `orangebox-ioc` — actualización periódica de listas IOC.

Los nombres, rutas y frecuencias mostrados en estos ejemplos deben adaptarse al entorno donde se desplieguen.

### Reportes

Los reportes se separan por cliente:

- `orangebox-reports-<cliente>` — contiene los reportes ejecutivos y detallados diarios, semanales y mensuales de un cliente.
- `orangebox-reports-orangebox` — puede contener los reportes consolidados internos.

No se publican direcciones de correo, nombres de clientes ni grupos reales en este repositorio. Los archivos de ejemplo usan valores genéricos.

## Ejemplo de reporte

```cron
# Reporte ejecutivo diario
15 1 * * * root /var/ossec/reports/orangebox-security-report.py --yesterday --group ClienteEjemplo --email soporte@example.invalid

# Reporte ejecutivo semanal - lunes
30 4 * * 1 root /var/ossec/reports/orangebox-security-report.py --lastweek --group ClienteEjemplo --email soporte@example.invalid

# Reporte ejecutivo mensual - día 1
0 8 1 * * root /var/ossec/reports/orangebox-security-report.py --lastmonth --group ClienteEjemplo --email soporte@example.invalid

# Reporte detallado diario
0 3 * * * root /var/ossec/reports/orangebox-detailed-security-report.py --yesterday --group ClienteEjemplo --email soporte@example.invalid

# Reporte detallado semanal - lunes
30 6 * * 1 root /var/ossec/reports/orangebox-detailed-security-report.py --lastweek --group ClienteEjemplo --email soporte@example.invalid

# Reporte detallado mensual - día 1
0 10 1 * * root /var/ossec/reports/orangebox-detailed-security-report.py --lastmonth --group ClienteEjemplo --email soporte@example.invalid
```

## Ejemplo de tarea de sistema

```cron
# Sincroniza automáticamente la CDB asociada al grupo cPanel.
# El script debe actualizar la lista y recargar Wazuh solo cuando haya cambios.
*/10 * * * * root /var/ossec/etc/lists/update-orangebox-cpanel-agents.sh >/dev/null 2>&1
```

## Instalación

Copiar los archivos al directorio de cron del sistema:

```bash
rsync -av configuration/manager/etc/cron.d/ /etc/cron.d/
chmod 644 /etc/cron.d/orangebox-*
chown root:root /etc/cron.d/orangebox-*
```

Comprobar que `crond` esté activo:

```bash
systemctl status crond --no-pager
```

Y revisar la ejecución:

```bash
journalctl -u crond --since "15 minutes ago" --no-pager
```

Las entradas de `/etc/cron.d/` deben incluir explícitamente el usuario (`root`) en cada línea.

## Regla de mantenimiento

No volver a acumular tareas OrangeBox en `crontab -e` de `root`. Para una nueva tarea, crear un archivo independiente en `configuration/manager/etc/cron.d/`.
