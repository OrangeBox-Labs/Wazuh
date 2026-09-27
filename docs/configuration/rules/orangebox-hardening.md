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

### Criterio para mantener estas excepciones

Las excepciones anteriores corresponden a falsos positivos validados en producción. No se debe extender una excepción a todo un directorio, proceso o usuario cuando el evento concreto puede expresarse mediante una ruta exacta y, cuando está disponible, una condición adicional sobre el contenido o el resultado de FIM.

Esto mantiene `10037` operativo para cambios reales de firewall y mantiene `10035` operativo para el resto de la configuración CRON.

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
