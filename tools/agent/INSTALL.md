# Instalación del agente Wazuh OrangeBox

El despliegue completo se realiza con un único instalador:

```bash
cd tools/agent
./install.sh
```

El instalador pregunta si el servidor es cPanel/CSF.

## Flujo

1. Detecta distribución, versión de Enterprise Linux y presencia/versión del Wazuh Agent.
2. Instala o reconcilia el agente estándar o el RPM OPT de cPanel.
3. Prepara y valida el almacenamiento dedicado de `/var/ossec` en Linux normal; el perfil OPT conserva `/opt/ossec`.
4. Detecta el backend de firewall y reconcilia el logging OrangeBox sin duplicar reglas.
5. Instala y valida auditd, sus reglas persistentes y la lectura local de `/var/log/audit/audit.log`.
6. Verifica conflictos e instala la rotación diaria de auditd, compresión gzip y retención local de siete días.
7. Reconcilia telemetría local de SYN-RECV, CPU de `ksoftirqd` y carga; agrega PHP-FPM solo en cPanel.
8. Mantiene `logcollector.remote_commands=0` en `local_internal_options.conf`; la telemetría se ejecuta localmente y no requiere comandos remotos.
9. Instala/valida YARA, genera el runtime y el actualizador del ruleset, y verifica sus índices.
10. Instala el Active Response de cuarentena para hashes confirmados.
11. Activa el agente una sola vez si hubo cambios y realiza las verificaciones finales.

El proceso es idempotente. Las etapas importantes están aisladas: si una etapa falla, se registra el error y el instalador continúa con las siguientes. Al final muestra un resumen de pasos OK y pasos con error y devuelve código `1` si quedó alguna etapa fallida.

## Firewall OrangeBox

El instalador aplica la precedencia **Shorewall > firewalld > iptables**.

### Shorewall

Cuando Shorewall está instalado, el instalador no utiliza `rules` ni Actions para implementar la cadena OrangeBox. Agrega de forma idempotente un bloque marcado en:

```text
/etc/shorewall/started
```

El bloque se ejecuta después de que Shorewall haya creado su firewall y:

- crea la cadena `ORANGEBOX-FW` si no existe;
- reconstruye solamente esa cadena para evitar duplicados;
- detecta dinámicamente la IP privada y la IP pública en cada arranque/reinicio de Shorewall;
- permite con `RETURN` el tráfico TCP SYN desde la IP pública del propio servidor hacia su IP privada;
- registra TCP SYN con `LOG` limitado a **20 eventos/s, burst 40**;
- termina con `RETURN` para no bloquear tráfico por sí mismo;
- conecta `INPUT` con `ORANGEBOX-FW` una sola vez.

Si existe la regla OrangeBox antigua en `/etc/shorewall/rules`, el instalador la retira después de respaldar el archivo. La configuración se valida con `shorewall check` antes de aplicar el reinicio.

La presencia del marcador:

```text
# BEGIN ORANGEBOX WAZUH FIREWALL
```

se utiliza para que una segunda ejecución no vuelva a insertar el bloque.

## auditd

El instalador mantiene un único archivo canónico:

```text
/etc/audit/rules.d/70-orangebox-wazuh.rules
```

Las reglas cubren:

- ejecución `execve` desde `/tmp`, `/var/tmp` y `/dev/shm` con la clave `orangebox_exec`;
- ejecución de herramientas de scanner y reconocimiento que estén realmente instaladas, con la clave `audit-wazuh-c`;
- arquitecturas `b64` y `b32` cuando el kernel/audit las soporte.

Las instalaciones antiguas que todavía tengan `99-orangebox-exec.rules` con reglas OrangeBox se respaldan y migran al archivo canónico para evitar el error de reglas duplicadas de `augenrules`.

En Enterprise Linux 10 se instala `audit-rules` cuando corresponde. El instalador también comprueba `audispd-plugins`, necesario para que Wazuh pueda usar Whodata mediante `audisp-af_unix`. Wazuh utiliza su propio plugin `/etc/audit/plugins.d/af_wazuh.conf`; el `af_unix.conf` genérico de `audispd-plugins` no se activa ni se modifica. Después de cargar las reglas, se valida que las claves OrangeBox estén activas y se reinicia Wazuh para consumir `/var/log/audit/audit.log`.

## Rotación/compresión de auditd

La política se instala en `/etc/cron.daily/orangebox-audit-logrotate`. Auditd rota el archivo activo mediante `service auditd rotate`; los archivos cerrados se comprimen con gzip y las generaciones OrangeBox con más de siete días se eliminan. El instalador desactiva la rotación por tamaño con `max_log_file_action = ignore` y recarga auditd con SIGHUP cuando cambia el parámetro.

Antes de modificar, busca referencias activas a `/var/log/audit` en `/etc/logrotate.conf` y `/etc/logrotate.d`, además de otros cron que ya roten auditd. Las configuraciones externas se conservan; si hay conflicto no se instala una segunda política y el paso se marca con error. También exige `crond` activo y habilitado. Si no lo está, el instalador no instala la tarea diaria ni cambia `max_log_file_action`.

## Telemetría local y ejecución remota

Las fuentes OrangeBox de comandos para SYN-RECV, CPU de `ksoftirqd` y carga se mantienen en el `ossec.conf` de cada agente. PHP-FPM se configura únicamente en los agentes cPanel/OPT. El instalador reconcilia los bloques marcados, detecta definiciones manuales duplicadas y conserva un respaldo antes de modificar el archivo.

El instalador fija `logcollector.remote_commands=0` en `local_internal_options.conf`. Las fuentes `command`/`full_command` de esta telemetría no se distribuyen desde `agent.conf`; por tanto, el manager no puede cambiarlas remotamente a través de esa configuración. La configuración central de cPanel conserva FIM y las fuentes de logs específicas de cPanel, pero no la telemetría de comandos ni una segunda entrada para `audit.log`.

El RPM OPT se utiliza únicamente cuando se selecciona cPanel:

```text
tools/agent/wazuh-agent_4.14.8-0_x86_64_OPT.rpm
```

## YARA

El script de integración se genera durante la instalación en:

```text
/var/ossec/active-response/bin/orangebox-yara.sh
```

o, en cPanel:

```text
/opt/ossec/active-response/bin/orangebox-yara.sh
```

No se requiere copiar scripts ni ejecutar otro instalador YARA.
