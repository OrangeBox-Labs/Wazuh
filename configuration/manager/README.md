# Manager

Configuración global del Wazuh Manager.

## Archivos

- **`ossec.conf`** — configuración principal del Manager, incluyendo alertas, correo, módulos, syscheck, indexer, autenticación de agentes e integraciones.
- **`ossec.md`** — documentación técnica del archivo y de las decisiones de configuración.
- **`etc/cron.d/`** — tareas programadas del Manager, separadas por función y cliente.
- **`etc/local_internal_options.conf`** — opciones internas locales del Manager; no es configuración distribuida a los agentes.
- **`bin/orangebox-log-rotation`** — comprime logs internos antiguos y conserva 7 días únicamente bajo `/var/ossec/logs/wazuh` y `/var/ossec/logs/firewall`; no elimina alertas, logs de Active Response ni `ossec.log`.

## Criterio

El Manager es el punto donde convergen los eventos de los agentes, los decoders/reglas nativos y las reglas OrangeBox. Su configuración debe mantenerse separada de la política distribuida de agentes y de la lógica de detección.

Cuando una funcionalidad requiere cambios tanto en Manager como en agentes, la documentación debe describir explícitamente esa dependencia.

## Cron del Manager

Las tareas programadas OrangeBox se mantienen en `etc/cron.d/` en lugar de concentrarse en el `crontab` personal de `root`.

La organización es deliberadamente simple:

- `orangebox-cpanel-agents` — genera dinámicamente la CDB de agentes pertenecientes al grupo Wazuh `cpanel`.
- `orangebox-backuppc` — actualiza la whitelist dinámica de BackupPC.
- `orangebox-geoip` — actualiza las bases/listas Geo-IP.
- `orangebox-ioc` — actualiza las listas IOC.
- `orangebox-log-rotation` — comprime y elimina los logs internos de Wazuh y firewall, conservando los últimos 7 días.
- `orangebox-reports-<cliente>` — contiene los reportes diarios, semanales y mensuales de cada cliente.
- `orangebox-reports-orangebox` — contiene los reportes consolidados enviados a soporte@example.com.

Esto evita un `crontab -l` gigantesco y permite revisar, desplegar y mantener cada tarea de forma independiente. Los archivos de `cron.d` deben conservar el usuario `root` explícito en la línea de ejecución.

### Regla de mantenimiento

Al agregar una nueva tarea programada del Manager, debe crearse un archivo independiente dentro de `etc/cron.d/` según su función. No se debe volver a acumular lógica en el `crontab` de `root`.

## Active Response: port scan

La regla `10453` correlaciona el posible escaneo de puertos; la regla hija `10456` es la que activa `firewall-drop` en el agente que origina la alerta. El bloqueo dura 3600 segundos. La regla `10454` activa `firewall-drop` directamente ante un SYN flood que alcanza el umbral definido.

La configuración se define en el `ossec.conf` del manager. Wazuh incluye `firewall-drop` como script de Active Response para Linux/Unix y utiliza la IP `srcip` del evento para aplicar el bloqueo.

Las exclusiones de IP de Active Response se gestionan mediante las listas globales de `white_list`. OrangeBox ya mantiene allí las direcciones internas autorizadas.
