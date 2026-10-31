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
srv27.example.invalid:cpanel
```

La pertenencia al grupo y la entrada CDB deben mantenerse sincronizadas.


## Reglas asociadas

El perfil `cpanel` se consume desde las reglas del Manager mediante la CDB `orangebox-agent-profiles`.

Actualmente condiciona:

- `20031`: comandos directos de WP Toolkit;
- `20035`: contexto operacional validado de WP Toolkit;
- `20032`: regeneración esperada de `cpanel_ssl_reissue` en hardening.

No existe una whitelist genérica de `/bin/sh -c`. Cada wrapper se valida por operación completa para impedir que una excepción legítima sea reutilizada para ejecutar un segundo comando.

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
