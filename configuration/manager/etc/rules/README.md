# OrangeBox Wazuh Rules

Este directorio contiene las reglas y firmas personalizadas de OrangeBox para Wazuh.

## Arquitectura

- `10000–19999`: detecciones y correlaciones OrangeBox.
- `20000–29999`: excepciones y whitelists.

Las excepciones se mantienen al final de los XML cuando modifican el comportamiento de una detección anterior.

## Perfiles y whitelists

Cuando una excepción corresponde a una aplicación que existe en múltiples agentes, se utiliza un contexto de endpoint respaldado por una CDB específica.

```text
evento
  ↓
regla de detección
  ↓
grupo Wazuh -> CDB
  ↓
usuario/comando/contexto validado
  ↓
level 0
```

Las excepciones actuales usan CDB separadas:

- `20055`: Zimbra / `nc localhost:7171`, restringida al grupo `zimbra` y al contexto exacto de `zmconfigd`.

- `orangebox-cpanel-agents`: agentes del grupo Wazuh `cpanel`.
- `orangebox-zimbra-agents`: agentes del grupo Wazuh `zimbra`.
- No existe una CDB global de perfiles para estas excepciones.

Esto evita whitelists globales para software que solo es legítimo en determinados endpoints.

## Archivos

### `orangebox-auth.xml`

Autenticación, escalamiento de privilegios y correlaciones SSH/SUDO/SU.

`10005` funciona como nodo común para todos los `sudo -> root`.

Las correlaciones SSH principales son:

- `10006`: fuerza bruta SSH seguida de login exitoso desde la misma IP dentro de 5 minutos.
- `10008`: tres logins SSH exitosos desde la misma IP hacia ubicaciones diferentes dentro de 5 minutos, correlacionados globalmente entre agentes.

`10008` es una detección para investigación y no tiene Active Response asociado.

Las excepciones de aplicación están separadas por perfil:

- `cpanel` / WP Toolkit: `20031`, `20035`.
- `zimbra` / Carbonio CE: `110100`, respaldada por `orangebox-zimbra-agents`.

Las excepciones de SSH conservan condiciones por IP de origen cuando el sistema autorizado es el origen y no el agente receptor.

BackupPC separa las IP estáticas de la IP dinámica administrada por DNS para evitar que el updater pueda destruir autorizaciones manuales.

### `orangebox-hardening.xml`

Detecciones relacionadas con modificaciones y eliminaciones de componentes y configuraciones críticas del sistema. Las modificaciones solo generan alertas OrangeBox cuando existe evidencia de cambio de contenido; los cambios exclusivos de inode, mtime o permisos no se alertan. Los archivos nuevos son la excepción y se detectan mediante FIM `554`.

### `orangebox-temporary-executable.xml`

Detecciones sobre archivos ejecutables creados en ubicaciones temporales o de alto riesgo.

### `orangebox-yara.xml`

Integra FIM con YARA mediante Active Response. `10420/10421` envían a YARA todos los archivos nuevos o modificados de las zonas temporales delicadas, sin exigir extensión ni permiso de ejecución. `10501` alerta coincidencias YARA.

Las firmas ejecutables se mantienen en los archivos `.yar` del mismo directorio y el decoder asociado vive en `configuration/decoders/orangebox-yara.xml`.

### `orangebox-web.xml`

Detecciones HTTP/Apache orientadas a reconocimiento, autenticación web y abuso de recursos sensibles.

### `orangebox-firewall.xml`

Detecciones de actividad de red a partir del decoder nativo `kernel`.

### `orangebox-ioc.xml`

Correlaciones OrangeBox sobre las CDB oficiales de Wazuh para IOCs maliciosos. Las reglas `10460`–`10463` combinan una detección de ataque existente con una IP presente en `etc/lists/malicious-ioc/malicious-ip`.

Las acciones de contención siguen perteneciendo a las reglas padre existentes (`5720`, `10025`, `10456`, `10457`); estas reglas no agregan un segundo `firewall-drop`. La detección de hashes y otras detecciones IOC que Wazuh ya entrega (`99901`–`99920`) no se duplican.

## Criterio de revisión de una whitelist

Una whitelist debe ser evaluada en este orden:

1. ¿Es una propiedad del endpoint? Si sí, considerar perfil CDB.
2. ¿Es una propiedad del origen de red? Mantener `srcip`.
3. ¿Es una propiedad del usuario? Exigir usuario además del perfil cuando esté disponible.
4. ¿Es un comando? Restringir el comando completo.
5. ¿Es un wrapper shell? Separarlo y rechazar comandos encadenados.

No convertir una excepción puntual en una whitelist de directorio, usuario o shell completa.

## Regla de oro

**Detectar primero, perfilar después, excepcionar con el mínimo alcance posible y automatizar la contención al final.**

### `orangebox-mail.xml`

Detecta fuerza bruta contra autenticación de correo usando correlaciones nativas de Wazuh. `10700` cubre Postfix y `10701` cubre Exim/Dovecot. Ambas disparan `firewall-drop` durante 24 horas y no generan correo individual.


### Reconocimiento de red

En `orangebox-behavior.xml`, la regla `10611` mantiene la observación de comandos de reconocimiento a nivel bajo. La correlación `10612` utiliza únicamente los comandos definidos en `orangebox-network-recon-programs` y `10614` exige además la cadena previa de elevación de privilegios y múltiples comandos de red.

Esto evita convertir secuencias normales como `find`, `ps`, `uname` e `id` en una alerta crítica de reconocimiento de red.
