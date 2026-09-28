# Política FIM OrangeBox

## Objetivo

La política de File Integrity Monitoring (FIM) está diseñada para detectar cambios que puedan facilitar:

- ejecución o inyección de código;
- persistencia después de un compromiso;
- modificación de autenticación o credenciales;
- escalada de privilegios;
- alteración de controles de seguridad o de la capacidad de auditoría.

No se pretende vigilar todo el filesystem. El alcance se divide entre un perfil común y perfiles específicos de plataforma.

## Cómo interpretar los modos

| Modo | Uso en OrangeBox | Datos |
|---|---|---|
| Realtime | Directorios pequeños o de alto valor donde importa detectar el cambio inmediatamente | Metadata FIM normal; Who-Data cuando está definido |
| Realtime + Who-Data | Persistencia, credenciales, controles de privilegios y configuración de seguridad | Metadata + usuario/proceso del cambio |
| Report changes | Configuraciones donde el contenido exacto del cambio aporta evidencia | Metadata + diff de texto |
| Scheduled | Archivos individuales o árboles que no necesitan respuesta inmediata | Hashes, tamaño, propietario, permisos y demás atributos FIM |
| Nodiff | Archivos que contienen secretos o material sensible | Se mantiene la integridad sin almacenar el diff |

Wazuh indica que realtime funciona sobre directorios, no sobre archivos individuales; por eso los archivos individuales críticos se dejan en modo scheduled. report_changes está limitado a archivos de texto y nodiff permite conservar la monitorización sin reportar el contenido. whodata aporta usuario y proceso asociados al cambio.

Referencias:
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
- https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/use-cases/reporting-file-changes.html
- https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html

## Interacción con el ossec.conf local

Los agentes Wazuh suelen traer por defecto los árboles /etc, /usr/bin, /usr/sbin, /bin y /sbin dentro del ossec.conf local.

La configuración centralizada se mezcla con la configuración local y la configuración compartida tiene precedencia; además, cuando una ruta aparece en ambos lugares, la ruta no desaparece automáticamente.

Por eso el perfil default redefine esos mismos paths mediante restrict, reduciendo los árboles heredados a nombres de archivos ligados a autenticación, identidad, privilegios y arranque. Las rutas críticas que necesitan realtime se declaran además de forma explícita en los bloques correspondientes.

El resultado buscado es:

1. evitar que el default de Wazuh vuelva a indexar miles de archivos;
2. mantener monitoreo inmediato de los directorios de alta prioridad;
3. conservar los scans programados para binarios y archivos individuales críticos.

Referencia:
- https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html

## Perfil default

### Realtime

Se mantienen en tiempo real:

- /tmp
- /var/tmp
- /dev/shm
- /root/.ssh
- /home/*/.ssh
- /etc/ssh
- /etc/sudoers.d
- /etc/pam.d
- /etc/polkit-1
- /etc/security
- /etc/systemd/system
- /etc/systemd/user
- /etc/cron.d
- /etc/cron.hourly
- /etc/cron.daily
- /etc/cron.weekly
- /etc/cron.monthly
- /var/spool/cron
- /etc/profile.d
- /etc/ld.so.conf.d
- /etc/modprobe.d
- /etc/modules-load.d
- /etc/udev/rules.d
- /etc/sysctl.d
- /etc/pki/ca-trust/source/anchors
- /usr/local/share/ca-certificates
- /etc/firewalld
- /etc/nftables
- /etc/ufw
- /etc/shorewall

Las zonas temporales no usan report_changes: interesa detectar la aparición o modificación del artefacto y, cuando corresponde, entregarlo a YARA; guardar diffs de todo lo que ocurre allí aumenta innecesariamente la base FIM.

### Scheduled

Se mantienen fuera de realtime:

- /etc/passwd
- /etc/group
- /etc/shadow
- /etc/gshadow
- /etc/sudoers
- /etc/sudoers.conf
- /etc/securetty
- /etc/crontab
- /etc/anacrontab
- /etc/profile
- /etc/bashrc
- /etc/bash.bashrc
- perfiles shell de root y usuarios
- /etc/ld.so.preload
- /etc/modules
- /etc/rc.local
- /etc/rc.d/rc.local
- /etc/hosts
- /etc/resolv.conf
- /etc/nsswitch.conf
- /etc/fstab
- /etc/crypttab
- /etc/sysctl.conf
- /etc/nftables.conf
- /etc/sysconfig/nftables
- /etc/sysconfig/nftables.conf
- /etc/sysconfig/iptables

Los binarios vinculados directamente con autenticación y privilegios se controlan por integridad, pero no se monitorizan árboles completos de binarios o librerías.

### Datos completos y datos restringidos

Configuraciones de seguridad como SSH, sudoers, PAM, systemd, cron y firewall usan report_changes=yes + whodata=yes cuando el diff es seguro y útil.

shadow y gshadow no reportan diff.

Las claves privadas de SSH deben estar excluidas de diffs mediante nodiff aunque pertenezcan a un árbol monitorizado.

## Persistencia y escalada

La selección prioriza mecanismos que pueden sobrevivir a un reinicio o convertir un proceso legítimo en una ruta de privilegio:

- systemd;
- cron y anacron;
- claves SSH;
- shell startup;
- ld.so.preload;
- módulos/udev;
- sudoers;
- PAM;
- Polkit;
- identidad de usuarios y grupos;
- binarios administrativos sensibles;
- configuración de firewall/DNS/montajes;
- configuración de auditoría y logging.

La configuración también contempla vigilar las rutas de auditd y rsyslog porque alterar la recopilación o redirección de logs puede formar parte de una intrusión.

## cPanel

El perfil cpanel agrega únicamente lo que cPanel/EasyApache necesita. El código de los
webroots /home/*/public_html queda fuera del FIM masivo; se mantienen solo los puntos
quirúrgicos de seguridad del perfil común (por ejemplo /home/*/.ssh y archivos de inicio
de shell).

El perfil cPanel agrega:

- /etc/apache2/conf;
- /etc/apache2/conf.d;
- /etc/apache2/modules;
- /etc/cpanel/ea4;
- /etc/php.d;
- /etc/php-fpm.d;
- configuración PHP principal;
- /var/cpanel/cpanel.config;
- /root/cpanel_profile/cpanel.config;
- /var/cpanel/disabled;
- ACLs de Exim;
- configuración persistente de Exim;
- CSF;
- configuración efectiva de Imunify360.

No se indexan los document roots con FIM. La detección YARA se concentra en las zonas
temporales de ejecución crítica definidas por la política YARA.

Referencias oficiales:
- https://docs.cpanel.net/ea4/basics/easyapache-4-file-system-layout/
- https://docs.cpanel.net/ea4/apache/advanced-apache-configuration/
- https://docs.cpanel.net/ea4/apache/advanced-apache-configuration-the-paths-conf-file/

## Webserver genérico

El perfil `webserver` se utiliza para Apache/Nginx fuera de cPanel. Agrega:

- `/var/www`, `/srv/www` y `/usr/share/nginx/html` filtrados a código/configuración ejecutable;
- configuración Apache o Nginx;
- configuración PHP/PHP-FPM;
- `/etc/letsencrypt` sin diffs para material privado.

No se debe asignar junto con `cpanel` salvo que el host realmente necesite ambos perfiles.

## Zimbra / Carbonio

/opt/zimbra y /opt/zextras no pertenecen al perfil default.

El perfil funcional zimbra es el único que añade:

- temporales de producto;
- webapps Jetty (jsp, jspx, war, class);
- /opt/*/conf;
- /opt/*/ssl;
- binarios concretos utilizados por la política de sudo.

La configuración SSL se monitoriza por integridad y Who-Data, pero se bloquea el reporte de diff para evitar exponer claves o secretos.

## Límite de entradas FIM

Wazuh guarda la información FIM en una base SQLite local. El límite de `file_limit` se expresa en cantidad de entradas, no en megabytes; el valor predeterminado documentado es 100000 entradas. Cuando se alcanza el límite, los archivos nuevos dejan de incorporarse a la base.

Para OrangeBox se fija explícitamente:

```xml
<file_limit>
  <enabled>yes</enabled>
  <entries>175000</entries>
</file_limit>
```

El valor 175000 se eligió como ampliación moderada del límite original, tomando como referencia el tamaño observado de la base de referencia del agente. El tamaño físico final de SQLite no debe interpretarse como un límite exacto en MiB.

Importante: `file_limit` no controla el número de watches de inotify. En hosts cPanel con muchos subdirectorios bajo `public_html`, un exceso de watches puede producir errores `(6700) ... maximum limit of inotify watches has been reached` aunque la base FIM tenga capacidad disponible. Ambos límites deben vigilarse por separado.

Referencia:
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

## Validación después del deploy

En cada agente:

/opt/ossec/bin/wazuh-control info 2>/dev/null || /var/ossec/bin/wazuh-control info
systemctl restart wazuh-agent

grep -Ei 'syscheck|realtime|whodata|database.*full' /opt/ossec/logs/ossec.log 2>/dev/null | tail -50

Para confirmar que la política ya no está saturando FIM:

du -sh /opt/ossec/queue/fim/db 2>/dev/null || du -sh /var/ossec/queue/fim/db

grep -Ei 'database.*full|database.*90%' /opt/ossec/logs/ossec.log 2>/dev/null | tail

La ruta de Wazuh cambia entre instalaciones normales (/var/ossec) y OrangeBox/cPanel (/opt/ossec).
