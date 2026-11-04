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

Debe cumplirse además que el agente pertenezca al grupo Wazuh `DNS`, verificado mediante la CDB dinámica `orangebox-dns-agents`. No se exceptúa el directorio completo ni otros servicios; las eliminaciones de otras unidades siguen generando la alerta crítica `10044`. La validación operacional inicial debe confirmar que estos cuatro archivos corresponden a la limpieza esperada de DNSOnly antes de desplegar la regla.

### 20058 — Limpieza de unidades de montaje Snap

La excepción cubre únicamente eventos de eliminación atribuidos al proceso `snapd` y archivos/unidades que coincidan con:

```text
/etc/systemd/system/snap-*.mount
/etc/systemd/system/snap-*.mount.<n>~
```

La regla exige el actor `process_name=snapd` y el patrón exacto de archivo, y solo rebaja la eliminación a nivel 0. No autoriza cambios de contenido, otras unidades de systemd ni eliminaciones realizadas por otros procesos. El campo de proceso proviene de la auditoría Who-Data; confirma que el agente tenga Who-Data habilitado para las rutas relevantes y valida el evento con `wazuh-logtest` antes de desplegarlo ampliamente.

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

## Dependencias

- Wazuh FIM/syscheck.
- Evento `550`: archivo modificado.
- Evento `553`: archivo eliminado.
- Who-Data para las rutas críticas configuradas en `agent.conf`.

Si cambia el formato de los eventos FIM en una futura versión de Wazuh, estas reglas deben volver a probarse.


### 20061 — Eliminación programada de enlaces de activación Snap

La excepción cubre exclusivamente eliminaciones FIM en modo scheduled de enlaces de unidades Snap bajo:

```text
/etc/systemd/system/multi-user.target.wants/
/etc/systemd/system/snapd.mounts.target.wants/
```

El nombre debe corresponder a snap-<paquete>-<revision>.mount; se aceptan guiones escapados como \\x2d. Se conserva nivel 3 para dejar evidencia en Wazuh sin generar correo SOC con el umbral habitual 12. No se exceptúan otras unidades ni eventos Who-Data.

### 20066 — Integración programada BitNinja / nftables

La regla 20066 reclasifica a nivel 5 únicamente el cambio programado en /etc/systemd/system/bitninja.service que añade el bloque exacto de comentarios, After=nftables.service y PartOf=nftables.service.

After= ordena el arranque de BitNinja después de nftables; PartOf= propaga operaciones stop/restart desde nftables a BitNinja. La regla exige modo scheduled, ruta exacta y diff completo. Cambios distintos siguen llegando a la regla crítica 10034.

### 20069 — Actualización Who-Data de BitNinja mediante dpkg

La regla 20069 suprime únicamente el evento Who-Data que cumple todas estas condiciones:

- El hostname del agente está incluido en la CDB local orangebox-bitninja-agents.
- mode=whodata y archivo exacto /etc/systemd/system/bitninja.service.
- Proceso modificador /usr/bin/dpkg, usuario root y UID efectivo 0.
- El diff coincide exactamente con el bloque de integración nftables descrito en 20066.

La CDB pública contiene un hostname de ejemplo bajo example.invalid, que no autoriza ningún agente real. Cada instalación debe reemplazarlo por el FQDN del endpoint validado y mantener esa CDB fuera de plantillas compartidas si los nombres son sensibles. No se debe copiar una lista privada de hostnames al repositorio público.

La regla tiene nivel 0 únicamente para ese evento exacto. Otros procesos, agentes no incluidos, rutas o diffs diferentes mantienen la detección crítica 10034. Antes del despliegue, validar el XML, la CDB y casos positivos/negativos con wazuh-logtest.
