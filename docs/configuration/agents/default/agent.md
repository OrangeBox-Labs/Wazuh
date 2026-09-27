# `agent.conf`

## Qué hace

Configuración base que se entrega a los agentes del grupo `default`.

La idea es simple: **FIM en tiempo real para lo que importa y sin ponerse a vigilar cada archivo del planeta**.

El archivo está organizado por categorías para que sea fácil saber qué se protege y por qué.

## Decisiones importantes

### Archivos nuevos en tiempo real

Se activa `alert_new_files` porque en este proyecto nos interesa especialmente detectar archivos que aparecen en lugares donde un atacante podría dejar un webshell, payload o herramienta temporal.

Se vigilan en tiempo real:

- `/tmp`
- `/var/tmp`
- `/dev/shm`
- `/opt/zimbra/data/tmp`
- `/opt/zextras/data/tmp`

Zimbra y Carbonio aparecen separados porque ambos utilizan directorios temporales distintos. Esto viene de los incidentes que motivaron estas reglas; no es una lista genérica puesta porque sí.

## Who-Data en rutas críticas

Las rutas relacionadas con autenticación, identidad, privilegios, firewall y persistencia utilizan `whodata="yes"`.

La idea es no quedarnos solamente con:

```text
archivo modificado
```

sino conservar también información sobre:

```text
usuario + proceso que realizó el cambio
```

En Linux, Wazuh usa `audit` como proveedor por defecto cuando no se especifica otro. Esto requiere que el endpoint tenga el subsistema Audit disponible. No forzamos eBPF en la configuración compartida porque el proyecto todavía debe cubrir también Enterprise Linux antiguo.

Las rutas protegidas con Who-Data incluyen principalmente:

- `/root`;
- SSH, SUDO, PAM y Polkit;
- archivos de identidad (`passwd`, `shadow`, `group`, `gshadow`);
- configuración de red y firewall;
- SYSTEMD y CRON;
- binarios privilegiados de Zimbra/Carbonio;
- artefactos de persistencia y autenticación SSH.

`who-data` complementa FIM. No reemplaza la integridad ni las reglas OrangeBox.

## Persistencia de credenciales

Se vigilan específicamente los directorios:

- `/root/.ssh`
- `/home/*/.ssh`

con el objetivo de detectar inmediatamente cambios en `authorized_keys` y otros artefactos SSH que puedan utilizarse para mantener acceso.

También se vigilan rutas clásicas de persistencia del sistema como:

- `/etc/systemd/system`
- `/etc/systemd/user`
- `/etc/cron.d`
- `/var/spool/cron`
- `/etc/ld.so.preload`
- perfiles de shell;
- mecanismos `rc.local` de sistemas antiguos.

En los directorios SSH no usamos `report_changes="yes"`: queremos saber **que cambió, cuándo y quién lo cambió**, pero no necesitamos convertir el correo de seguridad en una fotocopiadora de archivos sensibles.

## `/root` y configuración sensible

`/root` y las rutas de autenticación, privilegios, red, firewall y persistencia usan `report_changes="yes"` donde el diff aporta valor operativo.

Entre las rutas críticas están:

- `/etc/ssh` y `/etc/sshd`
- `/etc/sudoers` y `/etc/sudoers.d`
- `/etc/pam.d`
- `/etc/polkit-1`
- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`
- `/etc/systemd/system` y `/etc/systemd/user`
- `/etc/cron.d`, `/etc/crontab`, `/etc/anacrontab`
- configuración de red y DNS
- firewalls
- Apache/Nginx/PHP
- MySQL/MariaDB/PostgreSQL

Las reglas OrangeBox interpretan después estos eventos FIM. Este archivo **recoge evidencia**; las reglas deciden cuándo esa evidencia merece una alerta.

## Binarios de sudo -> root

Hay un bloque específico para los ejecutables que forman parte de la whitelist de `orangebox-auth.xml`.

Se monitorean individualmente, con diff y Who-Data activos.

La decisión de no vigilar todo `/opt/zimbra` o `/opt/zextras` es intencional: solamente protegemos los comandos que tienen permiso de convertirse en root mediante la whitelist. Si uno de ellos fuera reemplazado o modificado, el atacante podría transformar una herramienta legítima en una puerta de escalamiento.

Por eso estos archivos tienen doble protección:

1. `orangebox-auth.xml` controla **qué comando puede ejecutarse**.
2. `orangebox-hardening.xml` controla **si ese comando fue modificado o eliminado**.

## Firewall e iptables

Se monitorean las configuraciones de firewall, incluyendo:

- Shorewall
- firewalld
- UFW
- CSF
- iptables
- nftables
- Imunify360

Las rutas de firewall críticas tienen Who-Data para poder atribuir cambios a usuario/proceso además de registrar el contenido modificado.

`iptables` tiene además una regla específica en `orangebox-hardening.xml`, porque un `iptables-save` puede modificar timestamps y contadores sin que haya cambiado una regla real. El agente debe registrar el cambio; la regla decide si el cambio es relevante.

## Binarios y librerías

`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, librerías y certificados se monitorean en tiempo real, pero sin `report_changes` ni Who-Data.

La razón es práctica: obtener diff o trazabilidad de miles de binarios compilados puede generar muchísimo almacenamiento y ruido. Para estos archivos nos interesa primero saber **que cambiaron**; no necesitamos convertir cada actualización legítima del sistema en una tesis doctoral.

## Relación con las reglas OrangeBox

Este archivo no contiene detecciones. Produce eventos FIM que luego son interpretados por reglas como:

- `10030`–`10038` para modificaciones críticas.
- `10040`–`10047` para eliminaciones críticas.
- `10410` y `10432` para ejecutables en directorios temporales.

La separación es deliberada: **el agente recopila, las reglas piensan**.

## Qué NO hacer

No agregar una ruta crítica simplemente porque "podría ser útil". Cada ruta aumenta el trabajo del agente y puede aumentar el ruido.

Antes de agregar algo hay que responder:

- ¿Qué ataque queremos detectar?
- ¿Qué evento FIM produciría?
- ¿Tenemos una regla que lo interprete?
- ¿Necesitamos el diff?
- ¿Qué falso positivo podemos generar?
- ¿Necesitamos Who-Data para atribuir el cambio?

Si no tenemos respuesta, probablemente todavía no necesitamos esa ruta.

## Dependencias

- Wazuh Agent / Syscheck (FIM).
- Audit en Linux cuando se utiliza `whodata="yes"` con el proveedor por defecto.
- Reglas personalizadas de `configuration/rules/`.
- El contenido de este archivo se instala normalmente como configuración compartida del agente.

## Nota

Este archivo refleja la configuración actualmente versionada. No debe asumirse que todas las rutas son obligatorias para cualquier instalación Wazuh; varias corresponden específicamente al entorno OrangeBox, incluyendo Zimbra/Carbonio y los controles de sudo descritos arriba.
