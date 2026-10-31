# Perfil FIM y autenticación cPanel / WHM

Este perfil identifica agentes cPanel/WHM y aplica controles adicionales de FIM, autenticación, firewall y telemetría para servidores de hosting.

## Identificación y fuente de verdad

La pertenencia al grupo Wazuh `cpanel` es la fuente de verdad. El sincronizador `configuration/manager/bin/update-orangebox-cpanel-agents.sh` consulta ese grupo y genera la CDB dinámica `orangebox-cpanel-agents` con FQDN y hostname corto:

```text
servidor.example.invalid:cpanel
servidor:cpanel
```

El archivo resultante vive en `/var/ossec/etc/lists/orangebox-cpanel-agents` en el Manager y **se genera localmente; no se versiona en Git**. `ossec.conf` declara la CDB y las reglas de autenticación/FIM la consultan. La etiqueta `orangebox.profile=cpanel` identifica el tipo de agente en los eventos, pero no sustituye la validación CDB.

## FIM del sistema y stack de hosting

El `agent.conf` de cPanel incorpora los controles base de identidad, SSH, SUDO, PAM, SYSTEMD, CRON, firewall, red y persistencia. Agrega vigilancia específica de:

- Apache/EasyApache bajo `/etc/apache2/conf`, `/etc/apache2/conf.d`, `/etc/apache2/modules` y `/etc/cpanel/ea4`;
- PHP/PHP-FPM bajo `/etc/php.d`, `/etc/php-fpm.d`, `/etc/php.ini` y `/etc/php-fpm.conf`;
- configuración cPanel en `/var/cpanel`, configuración de Exim y ACLs;
- DNS/FTP, CSF y configuración efectiva de Imunify360.

Las rutas críticas usan `report_changes` y Who-Data cuando el contenido aporta evidencia y la atribución del cambio ayuda a investigarlo. Las claves y datos sensibles se protegen con `nodiff` cuando corresponde.

## Webroot: alcance intencionalmente limitado

No se monitoriza recursivamente todo `/home/*/public_html`, porque en hosting compartido eso produciría demasiado volumen. Se vigilan en tiempo real estos puntos de entrada de alto valor:

```text
/home/*/public_html/.htaccess
/home/*/public_html/wp-config.php
/home/*/public_html/index.php
/home/*/public_html/functions.php
```

El perfil no intenta sustituir los logs web ni el análisis de malware. El objetivo es vigilar rutas críticas y cambios de ejecución con atribución Who-Data, sin indexar todo el contenido de los clientes.

## Excepciones de autenticación WP Toolkit

Las reglas `20031` y `20035` usan la CDB `orangebox-cpanel-agents` para reconocer el perfil cPanel:

- `20031`: permite únicamente comandos directos de WP Toolkit que forman parte de la allowlist revisada.
- `20035`: permite operaciones de WP Toolkit cuando coinciden usuario, destino, directorio de trabajo y comando en el contexto operacional validado.

No existe una whitelist genérica para `/bin/sh -c`. Un comando fuera de las condiciones aprobadas continúa generando la alerta `10005` de SUDO hacia root.

## Excepciones FIM cPanel / CloudLinux

Las reglas del Manager limitan las excepciones a las rutas concretas siguientes y requieren que el agente aparezca en `orangebox-cpanel-agents`:

| SID | Regla padre | Archivo / condición | Resultado |
|---|---:|---|---|
| `20032` | `10035` modificación | `/etc/cron.d/cpanel_ssl_reissue` | Nivel 0; regeneración rutinaria de cPanel. |
| `20050` | `10030` modificación | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Nivel 0; actualizaciones de cuentas por cPanel. |
| `20051` | `10037` modificación | `/etc/csf/csf.deny` | Nivel 0; actualizaciones de CSF/LFD. |
| `20052` | `10037` modificación | `/etc/sysconfig/nftables.conf` | Nivel 0; regeneración operacional de counters. |
| `20059` | `10045` eliminación | `/etc/cron.d/cpanel_php_sessions_cron` | Nivel 3; evidencia conservada, sin correo crítico. |
| `20060` | `10035` modificación | `lvemanager-cron`, `lvemanager-selector`, `cloudlinux-cron` bajo `/etc/cron.d/` | Nivel 3; evidencia conservada, sin correo crítico. |

`20060` no cubre eliminaciones de los archivos LVE Manager: siguen generando `10045`. Ninguna excepción ignora todo `/etc/cron.d/`.

## Telemetría local

El instalador unificado `tools/agent/install.sh` crea en el propio agente las fuentes de SYN-RECV, CPU de `ksoftirqd`, carga y PHP-FPM. No deben duplicarse como comandos en `agent.conf`: el instalador mantiene `logcollector.remote_commands=0`.

## Validación

En el Manager:

```bash
/var/ossec/bin/agent_groups -l -g cpanel
/var/ossec/bin/update-orangebox-cpanel-agents.sh
grep -F 'servidor.example.invalid:cpanel' /var/ossec/etc/lists/orangebox-cpanel-agents
/var/ossec/bin/wazuh-analysisd -t
```

Probar con `wazuh-logtest` tanto las condiciones positivas de las excepciones como hostnames no cPanel, rutas CRON ajenas y eliminaciones de los archivos LVE Manager.
