# OrangeBox Hardening

Documentación de `orangebox-hardening.xml`.

## Para qué sirve

Estas reglas usan Wazuh FIM para detectar cambios o eliminaciones en archivos que pueden afectar identidad, autenticación, persistencia, red o escalamiento de privilegios.

No intentan reemplazar FIM: **FIM detecta el cambio y estas reglas deciden cuándo ese cambio merece una alerta OrangeBox**.

## Cambios detectados

### 10030–10036 — Configuración crítica

Estas reglas cubren modificaciones en:

- identidad: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` y archivos asociados;
- SSH;
- SUDO;
- PAM;
- SYSTEMD;
- CRON/ANACRON;
- red, DNS y montajes.

Parten del evento FIM `550` (archivo modificado), pero solo generan la alerta OrangeBox cuando `changed_fields` contiene evidencia de cambio de contenido (size/md5/sha1/sha256). Cambios exclusivos de inode, mtime o permisos no generan estas alertas.

### 20062, 20064, 20080 y 20082 — Normalización GCP de `/etc/hosts`

Estas excepciones no dependen de una CDB de perfil ni de la extracción del hostname del evento FIM. La reducción de severidad exige que el evento corresponda a `/etc/hosts` y que el diff completo demuestre una transformación sin cambio funcional:

- `20062`: reescritura exacta de entradas MDS/hostname por `/usr/bin/sed`, como root y UID efectivo 0; nivel 3.
- `20064`: evento Who-Data atribuido a `wazuh-syscheckd`, root y UID efectivo 0; nivel 5 para revisión.
- `20080`: evento Who-Data que declara explícitamente `No content changes`, con proceso reconocido y usuario root; nivel 3.
- `20082`: evento `scheduled/realtime` sin Who-Data; solo se rebaja cuando el diff GCP completo coincide; nivel 3.

El diff validado contempla reemplazo de la entrada MDS conservando `169.254.169.254 metadata.google.internal`, reemplazo de hostname conservando IP/FQDN/alias, hunks `c` y reordenamiento conjunto MDS/hostname. No se acepta cambio de IP, FQDN o alias, línea agregada/eliminada sin contraparte, diff adicional ni evento sin evidencia verificable. En esos casos sigue activa la alerta crítica `10036`.

Los niveles 3 y 5 conservan evidencia en Wazuh por debajo del umbral de correo 12 cuando la regla hija coincide. Como segunda barrera, `custom-orangebox-email.py` aplica `orangebox_fim_email_filter.py` exclusivamente al envío de correo: si el evento sigue llegando como `10036`, solo se silencia el correo cuando el diff completo demuestra que Google retiró y reinsertó la misma línea MDS/hostname, sin cambiar IP, FQDN ni alias. En Who-Data exige `root`, UID efectivo 0 y proceso `/usr/bin/sed` o `wazuh-syscheckd`; en `scheduled/realtime` exige el diff exacto completo. La alerta original permanece en `alerts.json` y en el indexer. Cualquier dato faltante, actor desconocido, otro archivo o modificación funcional sigue el flujo normal de correo.

### 10037 — Firewall

Detecta cambios en configuraciones de Shorewall, firewalld, UFW, CSF, nftables e Imunify360.

Para Imunify360, la regla vigila exclusivamente la configuración efectiva del firewall:

```text
/etc/sysconfig/imunify360/imunify360.config
/etc/sysconfig/imunify360/imunify360.config.d/
```

No se incluye de forma genérica todo `/etc/sysconfig/imunify360/` porque ese árbol también contiene archivos internos generados por el malware scanner, como `malware-filters-admin-conf/processed/` y `processed.tmp/`. Esos archivos no representan por sí mismos una modificación de la configuración del firewall.

`/etc/sysconfig/iptables` queda fuera porque necesita un tratamiento distinto.

### 10038 — Cambio real en iptables

`iptables-save` puede modificar `/etc/sysconfig/iptables` aunque nadie haya cambiado una regla: pueden variar timestamps y contadores de paquetes.

Eso generaba ruido. La regla actual mira `changed_content` y solo alerta cuando el diff contiene líneas de reglas iptables (`-A`, `-C`, `-D`, `-I`, `-R`, `-F`, `-N`, `-X`, `-P`).

Así se diferencia entre:

```text
guardar el firewall
```

y

```text
cambiar el firewall
```

Se probó específicamente este comportamiento antes de dejar la regla.

### 10046–10047 — Integridad de comandos sudo autorizados

Los comandos incluidos en la whitelist de `orangebox-auth.xml` son una superficie de escalamiento: si un atacante modifica uno de esos binarios, el comando podría seguir pareciendo autorizado ante sudo.

Por eso:

- `10046` alerta cuando uno de esos archivos es modificado (`550`);
- `10047` alerta cuando es eliminado (`553`).

La misma política se aplica a los componentes equivalentes bajo:

- `/opt/zimbra`;
- `/opt/zextras` para Carbonio CE.

Ambas reglas son nivel 15 y pertenecen a `privilege_escalation_root` para que la integración de correo las trate como críticas.

La lista debe mantenerse sincronizada con la whitelist de comandos de `10005`.

### 10048–10049 — Persistencia de credenciales SSH

Estas reglas vigilan `authorized_keys` bajo:

```text
/root/.ssh/authorized_keys
/home/<usuario>/.ssh/authorized_keys
```

El agente monitoriza los directorios `.ssh` con `whodata="yes"` y sin `report_changes`, por lo que podemos conservar la atribución de usuario/proceso sin mandar el contenido de las claves en el diff.

- `10048` detecta modificación de `authorized_keys` (`550`) solamente cuando cambió su contenido;
- `10049` detecta eliminación de `authorized_keys` (`553`).

El objetivo no es asumir que toda modificación es maliciosa. Una clave puede cambiar legítimamente. La regla existe para que ese cambio quede claramente identificado como un evento de persistencia de credenciales y pueda correlacionarse con el contexto de autenticación correspondiente.

## Eliminaciones

Las reglas `10040–10045` cubren la eliminación de los mismos grupos de configuración protegidos mediante el evento FIM `553`.

Eliminar un archivo crítico se trata con mayor severidad que modificarlo, porque puede dejar el control de acceso, autenticación o persistencia directamente inutilizado.

## Excepciones / whitelist

Las excepciones usan IDs `20000–29999`, quedan al final del XML y apuntan explícitamente a la regla de detección correspondiente.

### 20032 — cPanel `cpanel_ssl_reissue`

Silencia `10035` solamente cuando el evento cumple simultáneamente:

```text
perfil CDB = cpanel
+
/etc/cron.d/cpanel_ssl_reissue
```

cPanel regenera este cron durante tareas normales de renovación/reemisión SSL. La excepción no afecta al resto de `/etc/cron.d/` ni a otros agentes que tengan un archivo con el mismo nombre.

La condición de perfil evita convertir una excepción específica de cPanel en una whitelist global.

### 20059 — Eliminación del cron de sesiones PHP de CloudLinux/CageFS

La regla `20059` aplica sobre `10045` (eliminación FIM `553`) y requiere simultáneamente:

```text
perfil CDB = cpanel
+
/etc/cron.d/cpanel_php_sessions_cron
```

La excepción utiliza nivel 3: el evento permanece registrado en Wazuh, pero no alcanza el umbral 12 de la integración de correo. No se exceptúan otros cron de PHP ni otras rutas de `/etc/cron.d/`.

### 20060 — Modificaciones de cron de CloudLinux LVE Manager

La regla `20060` aplica sobre `10035` (modificación FIM `550`) y se limita a:

```text
/etc/cron.d/lvemanager-cron
/etc/cron.d/lvemanager-selector
/etc/cron.d/cloudlinux-cron
```

También exige el perfil CDB `cpanel` y utiliza nivel 3 para conservar la evidencia en Wazuh sin generar correo crítico. Esta excepción cubre únicamente modificaciones. Las eliminaciones de esos archivos continúan sujetas a `10045` y no quedan autorizadas por `20060`.

### 20057 — Limpieza de plugins cPanel SocialBee/XOVI en DNSOnly

La regla nativa OrangeBox `10044` detecta la eliminación de unidades persistentes de systemd. La excepción `20057` cubre únicamente estos archivos bajo `/etc/systemd/system/`:

```text
initialize_socialbee_plugin.service
initialize_socialbee_plugin.timer
initialize_xovi_plugin.service
initialize_xovi_plugin.timer
```

Debe cumplirse además que el agente pertenezca al grupo Wazuh `DNS` (mayúsculas), verificado mediante la CDB dinámica `orangebox-dns-agents`. El actualizador consulta ese mismo grupo y genera valores `DNS` en la CDB; la regla valida exactamente ese valor. Los eventos observados pueden presentar el nombre del archivo con el sufijo `;` más ocho caracteres hexadecimales (por ejemplo, `initialize_socialbee_plugin.service;6aebbc7e`); la expresión acepta el sufijo únicamente en los cuatro nombres permitidos. No se exceptúa el directorio completo ni otros servicios; las eliminaciones de otras unidades siguen generando la alerta crítica `10044`.

### 20058 — Limpieza de unidades de montaje Snap atribuida a snapd

La excepción cubre únicamente eventos de eliminación atribuidos al ejecutable `snapd` y archivos/unidades que coincidan con:

```text
/etc/systemd/system/snap-*.mount
/etc/systemd/system/snap-*.mount.<n>~
```

Who-Data puede entregar el nombre corto `snapd` o la ruta absoluta del ejecutable de una revisión activa, por ejemplo:

```text
/snap/snapd/28254/usr/lib/snapd/snapd
```

La regla acepta ambos formatos, pero sigue exigiendo el actor y el patrón de archivo. Solo rebaja la eliminación a nivel 0 cuando Who-Data confirma que el responsable es Snap. No autoriza cambios de contenido, otras unidades de systemd ni eliminaciones realizadas por otros procesos.

### 20061 — Eliminación de enlaces de activación Snap sin Who-Data

Snap también mantiene enlaces de activación de unidades de montaje en estos directorios:

```text
/etc/systemd/system/multi-user.target.wants/snap-<paquete>-<revision>.mount
/etc/systemd/system/snapd.mounts.target.wants/snap-<paquete>-<revision>.mount
```

Systemd escapa los guiones que forman parte del nombre del paquete como `\x2d`. Por eso Google Cloud CLI puede aparecer como `snap-google\x2dcloud\x2dcli-513.mount`, en lugar de `snap-google-cloud-cli-513.mount`.

Algunos eventos FIM de estos enlaces llegan en modo `scheduled`, sin datos de auditoría del proceso. La regla `20061` exige además que el evento sea `mode=scheduled`; se limita a esos dos directorios, a nombres Snap con revisión numérica y acepta tanto guiones literales como guiones escapados `\x2d`. Las eliminaciones siguen heredando de `10044`.

Se conserva nivel 3: el evento permanece disponible en Wazuh, pero no alcanza el umbral 12 de la integración de correo. No se infiere ni se inventa un proceso responsable. Las eliminaciones de otras rutas, unidades o directorios .wants siguen generando la alerta crítica.

### Criterio para mantener estas excepciones

Las excepciones anteriores corresponden a falsos positivos validados en producción. No se debe extender una excepción a todo un directorio, proceso o usuario cuando el evento concreto puede expresarse mediante una ruta exacta y, cuando está disponible, una condición adicional sobre el contenido o el resultado de FIM.

Esto mantiene `10037` operativo para cambios reales de firewall y mantiene `10035` operativo para el resto de la configuración CRON, excepto las tres rutas CloudLinux concretas cubiertas por `20060`. Las eliminaciones siguen protegidas por `10045`, salvo el cron de sesiones PHP exacto cubierto por `20059`.

## Política FIM para modificaciones

Las reglas OrangeBox basadas en el evento FIM `550` se limitan a cambios de contenido. La evidencia utilizada es `changed_fields`, donde Wazuh expone campos como `size`, `md5`, `sha1` y `sha256` cuando el contenido cambia. El objetivo es evitar alertas por operaciones rutinarias que solo alteren metadatos.

Los archivos nuevos siguen siendo una excepción: se detectan mediante el evento `554`, aunque todavía no exista un estado anterior con el cual comparar su contenido.

## Decisiones importantes

### No filtrar por UID o proceso

El cambio relevante es el archivo y su contenido, no quién lo modificó. Filtrar por UID o proceso podría ocultar una modificación maliciosa realizada desde una cuenta o proceso comprometido.

Who-Data se utiliza justamente para **observar y atribuir**, no para convertir el origen en una whitelist.

### FIM primero, regla después

Estas reglas aprovechan los eventos nativos `550` y `553`. No se crea otro mecanismo paralelo para vigilar los mismos archivos.



### 20069 — Actualización Whodata BitNinja mediante dpkg

La excepción `20069` suprime el evento Who-Data observado en `webserver.example.invalid` cuando `/usr/bin/dpkg` ejecutado como root añade exactamente el mismo bloque de integración con nftables a `/etc/systemd/system/bitninja.service`.

El evento puede llegar como `mode=whodata` cuando la instalación se realiza mediante `apt-get`/`dpkg`, por lo que no coincide con la excepción `20066`, que cubre el escaneo programado. La regla nueva tiene nivel 0 y evita que este cambio operacional genere una alerta. Exige agente, modo, proceso, usuario, UID, ruta y diff exactos. No filtra otras unidades, otros procesos ni cambios de `ExecStart` u otras directivas; estos siguen protegidos por la regla crítica `10034`.

## Dependencias

- Wazuh FIM/syscheck.
- Evento `550`: archivo modificado.
- Evento `553`: archivo eliminado.
- Who-Data para las rutas críticas configuradas en `agent.conf`.

Si cambia el formato de los eventos FIM en una futura versión de Wazuh, estas reglas deben volver a probarse.

### 20066 — Integración programada BitNinja / nftables

La regla `20066` reclasifica a nivel 5 únicamente la modificación programada observada en `/etc/systemd/system/bitninja.service` que añade el bloque completo de comentarios, `After=nftables.service` y `PartOf=nftables.service`.

La relación tiene sentido operacional: `After=` ordena el arranque de BitNinja después de nftables y `PartOf=` propaga las operaciones stop/restart desde nftables hacia BitNinja. Esto permite que BitNinja vuelva a cargar sus tablas cuando nftables reconstruye el ruleset. BitNinja documenta su integración de firewall mediante nftables y una tabla propia; la semántica de `PartOf=` hace que las operaciones stop/restart se propaguen a la unidad relacionada.

La excepción exige `mode=scheduled`, el archivo exacto y el diff completo de las seis líneas añadidas, incluidos sus comentarios. No silencia cambios de `ExecStart`, otras directivas, otras unidades ni modificaciones parciales del bloque. Es un evento de revisión nivel 5: permanece en Wazuh y no genera correo con el umbral actual 12.

### 20070 — Limpieza de temporales \`.dpkg-new\` en SYSTEMD

La alerta observada en \`webserver.example.invalid\` no correspondía a la eliminación de unidades activas. Los cuatro eventos eran archivos de staging terminados en \`.dpkg-new\`, eliminados por \`/usr/bin/dpkg\` cuyo proceso padre era \`/usr/bin/apt-get\`, ambos ejecutados como root.

La regla 20070 hereda de \`10044\`, pero solo rebaja a nivel 3 cuando coinciden el agente exacto, \`mode=whodata\`, las cuatro rutas SocialBee/XOVI con sufijo \`.dpkg-new\`, \`process_name=/usr/bin/dpkg\`, \`parent_name=/usr/bin/apt-get\`, usuario root y UID efectivo 0. El nivel 3 conserva el evento para auditoría, pero queda bajo el umbral de correo.

No cubre los archivos definitivos \`.service\`/\`.timer\`, otras unidades, \`.dpkg-old\`, \`.dpkg-tmp\`, otros procesos ni eventos sin Who-Data. Las eliminaciones reales de unidades SYSTEMD siguen siendo críticas bajo \`10044\`.

### 20071 — Limpieza del temporal WP Toolkit en CRON

La alerta observada en `cpanel.example.invalid` correspondía a la eliminación de
`/etc/cron.d/wp-toolkit-update.dpkg-new`, un archivo temporal de staging de
`dpkg`, no al cron activo `/etc/cron.d/wp-toolkit-update`. Who-Data atribuyó
la operación a `/usr/bin/dpkg`, con padre `/usr/bin/apt-get`, ejecutados como
root.

La regla `20071` hereda de `10045` y rebaja el evento a nivel 3 únicamente
cuando coinciden el agente exacto, `mode=whodata`, la ruta temporal exacta,
`process_name=/usr/bin/dpkg`, `parent_name=/usr/bin/apt-get`, usuario root y
UID efectivo 0. El nivel 3 conserva la evidencia en Wazuh, pero queda bajo el
umbral 12 de la integración de correo.

No se exceptúa `/etc/cron.d/wp-toolkit-update`, otros archivos `.dpkg-new`,
otros sufijos temporales, otros agentes, otros procesos ni eventos sin
Who-Data. Las eliminaciones reales de tareas CRON siguen siendo críticas bajo
`10045`.
