# Perfil cPanel

Este perfil identifica agentes que ejecutan cPanel/WHM.

## Objetivo

La etiqueta `orangebox.profile=cpanel` permite reconocer el perfil funcional del agente en las alertas.

La supresión de falsos positivos del SUDO de WP Toolkit no depende únicamente de esta etiqueta: las reglas del Manager utilizan la CDB `orangebox-agent-profiles`, porque las reglas deben disponer de una condición evaluable durante el análisis del evento.

## Asignación

El agente debe pertenecer al grupo Wazuh `cpanel` y su hostname debe estar registrado en:

```text
configuration/lists/orangebox-agent-profiles
```

Ejemplo:

```text
srv27.example.invalid:cpanel
srv28.example.invalid:cpanel
```

La pertenencia al grupo y la entrada CDB deben mantenerse sincronizadas.


## Reglas asociadas

El perfil `cpanel` se consume desde las reglas del Manager mediante la CDB `orangebox-agent-profiles`.

Actualmente condiciona:

- `20031`: comandos directos de WP Toolkit;
- `20035`: contexto operacional validado de WP Toolkit;
- `20032`: regeneración esperada de `cpanel_ssl_reissue` en hardening.

No existe una whitelist genérica de `/bin/sh -c`. Cada wrapper se valida por operación completa para impedir que una excepción legítima sea reutilizada para ejecutar un segundo comando.

## Dos CDB distintas para dos funciones

El perfil cPanel utiliza dos listas con responsabilidades distintas. No son intercambiables:

- `orangebox-agent-profiles` (`configuration/lists/orangebox-agent-profiles`) asocia `hostname:cpanel` y la consultan las reglas de autenticación/SUDO que validan el perfil funcional.
- `orangebox-cpanel-agents` (`configuration/manager/etc/lists/orangebox-cpanel-agents`) se genera desde el grupo Wazuh `cpanel` mediante `update-orangebox-cpanel-agents.sh`. La usan las excepciones FIM del ruleset `orangebox-hardening.xml`.

Para que funcionen las excepciones CRON, el agente debe pertenecer al grupo Wazuh `cpanel` y aparecer en la CDB dinámica `orangebox-cpanel-agents`. La etiqueta `orangebox.profile=cpanel` ayuda a identificar el perfil en los eventos, pero no reemplaza la condición CDB del Manager.

## Cobertura FIM del perfil

El `agent.conf` de cPanel mantiene los controles base de identidad, SSH, SUDO, PAM, SYSTEMD, CRON, firewall, red y persistencia. Para hosting compartido añade controles de Apache/EasyApache, PHP/PHP-FPM, Exim, CSF e Imunify360.

No monitoriza recursivamente todo `/home/*/public_html`. El webroot se limita a los puntos de entrada de alto valor documentados en este archivo; el instalador mantiene además telemetría local de SYN-RECV, CPU, carga y PHP-FPM cuando corresponde.

## Excepciones FIM CRON de cPanel / CloudLinux

Las reglas del Manager aplican solo a agentes que coinciden con `orangebox-cpanel-agents` y con las rutas exactas:

| SID | Evento padre | Ruta | Resultado |
|---|---:|---|---|
| `20032` | `10035` modificación | `/etc/cron.d/cpanel_ssl_reissue` | Nivel 0: regeneración conocida de cPanel. |
| `20059` | `10045` eliminación | `/etc/cron.d/cpanel_php_sessions_cron` | Nivel 3: se conserva evidencia en Wazuh sin correo crítico. |
| `20060` | `10035` modificación | `lvemanager-cron`, `lvemanager-selector`, `cloudlinux-cron` bajo `/etc/cron.d/` | Nivel 3: se conserva evidencia en Wazuh sin correo crítico. |

`20060` no cubre eliminaciones de los tres archivos LVE; siguen generando la alerta `10045`. Ninguna excepción ignora el directorio completo `/etc/cron.d/`.

## Telemetría del agente

El instalador `tools/agent/install.sh` crea localmente las fuentes de estado SYN-RECV, uso de `ksoftirqd`, carga y PHP-FPM. No deben duplicarse como comandos remotos en `agent.conf`: la instalación conserva `logcollector.remote_commands=0`.

## Validación

Después de asignar el agente al grupo `cpanel`, ejecutar el sincronizador dinámico y comprobar la CDB:

```bash
/var/ossec/bin/update-orangebox-cpanel-agents.sh
grep -F '<hostname-del-agente>:' /var/ossec/etc/lists/orangebox-cpanel-agents
/var/ossec/bin/wazuh-analysisd -t
```

Probar los SIDs `20032`, `20059` y `20060` con `wazuh-logtest` usando muestras positivas y rutas CRON ajenas como casos negativos.
## Validación del perfil

```text
cpanel + comando permitido       -> level 0
otro perfil + mismo comando      -> 10005
cpanel + comando no permitido    -> 10005
cpanel + wrapper + comando extra -> 10005
```

## FIM del stack web y del webroot

El perfil no vigila recursivamente todo `/home/*/public_html`: ese alcance produciría demasiado volumen y ruido en hosting compartido. La cobertura del webroot se limita a cuatro puntos de entrada de alto valor:

```text
/home/*/public_html/.htaccess
/home/*/public_html/wp-config.php
/home/*/public_html/index.php
/home/*/public_html/functions.php
```

Estos archivos usan realtime, `report_changes` y Who-Data. El resto de la configuración del stack se vigila por separado: Apache/EasyApache, PHP/PHP-FPM, Exim ACLs, cPanel, CSF y la configuración efectiva de Imunify360. Las reglas `orangebox-hardening.xml` interpretan los eventos y determinan cuáles requieren alerta.

## Telemetría local

El instalador único `tools/agent/install.sh` genera en el propio agente las fuentes locales de SYN-RECV, CPU de `ksoftirqd` y carga. En cPanel también configura telemetría de procesos PHP-FPM. Las fuentes llevan los alias `orangebox-synrecv`, `orangebox-synrecv-total`, `orangebox-ksoftirq`, `orangebox-load` y, solo en cPanel, `orangebox-phpfpm`.

No deben copiarse esas fuentes a este `agent.conf`: se mantienen localmente y el instalador fija `logcollector.remote_commands=0`. Esto evita que una actualización del grupo vuelva a duplicar comandos o permita ejecución remota.

## Excepciones FIM cPanel/CloudLinux

Las excepciones de cron se implementan en el Manager y solo aplican a agentes incluidos en el perfil CDB `cpanel`:

- `20032`: regeneración de `/etc/cron.d/cpanel_ssl_reissue`;
- `20059`: eliminación del cron `/etc/cron.d/cpanel_php_sessions_cron`, reteniendo el evento en nivel 3;
- `20060`: modificación de `lvemanager-cron`, `lvemanager-selector` y `cloudlinux-cron`, también reteniendo el evento en nivel 3.

La regla detectora `10045` sigue alertando eliminaciones de los otros cron, incluidas eliminaciones de los tres archivos de LVE Manager. La excepción `20060` solo cubre modificaciones.

## Validación

Después de modificar el perfil, comprobar que el agente pertenece al grupo Wazuh `cpanel`, que su nombre está en la CDB y que no hay bloques de telemetría local duplicados:

```bash
/var/ossec/bin/agent_groups -l -i <AGENT_ID>
grep -F '<alias>orangebox-' /var/ossec/etc/shared/cpanel/agent.conf
/var/ossec/bin/wazuh-analysisd -t
```
