# Detección de fuerza bruta de correo

Este componente agrega una capa OrangeBox sobre las reglas nativas de Wazuh para detectar múltiples fallos de autenticación contra servicios de correo.

## Detecciones

- `10700`: Postfix detectó múltiples fallos de autenticación SASL. Se basa en la regla nativa `3357`.
- `10701`: Exim/Dovecot detectó múltiples fallos de autenticación. Se basa en la regla nativa `87507`.

Las dos reglas quedan en nivel 13 y disparan `firewall-drop` durante 24 horas. La integración OrangeBox NO envía correo individual para estos eventos porque son recurrentes.

## Contención

`firewall-drop` se aplica automáticamente en el mismo servidor que generó el evento, con un bloqueo de 24 horas. La alerta sigue quedando en Wazuh; solo se suprime el correo individual para evitar ruido.

## Dependencias

La detección depende de que el servidor genere logs compatibles con las reglas nativas de Wazuh y de que esas reglas estén activas.

Postfix usa la regla nativa `3332` para un fallo individual y `3357` para múltiples fallos SASL. La capa OrangeBox usa `3357` para elevar el evento correlacionado a nivel 13.

## Prueba

Antes de desplegar a todos los servidores de correo:

1. Validar la regla con `wazuh-logtest`.
2. Generar varios fallos controlados.
3. Confirmar `10700` o `10701` en `alerts.json`.
4. Confirmar la ejecución de `firewall-drop` mediante la regla `651`.
5. Confirmar que NO llega correo individual por la integración OrangeBox.

Si un formato real de Dovecot o Exim no entrega correctamente `srcip`, se debe corregir primero la extracción antes de automatizar contención.

## Anomalía IDN de SpamAssassin (regla 20056)

La regla nativa `40106` detecta una secuencia extensa de arrobas y la etiqueta como posible desbordamiento de búfer en yppasswd. Cuando el evento proviene de `spamd` y contiene el error `idn_to_ascii: conversion to ACE failed`, la regla `20056` rebaja el nivel a 5 porque el log acredita un fallo de conversión del nombre IDN, no un desbordamiento confirmado.

El evento **no se suprime**: sigue disponible como alerta para revisar el correo asociado. Esta excepción no declara el mensaje legítimo ni reemplaza la revisión de cabeceras, cuerpo, origen y destinatarios. Los eventos `40106` que no cumplan esas condiciones mantienen el comportamiento nativo.

## Recolección central de logs MTA (Zimbra / Carbonio)

El perfil compartido `zimbra` recoge de forma centralizada, mediante Logcollector del agente Wazuh existente, las fuentes MTA consolidadas:

- Zimbra: `/var/log/maillog` y `/var/log/zimbra.log` (Postfix y Amavis, según el enrutamiento syslog).
- Carbonio CE: `/var/log/carbonio.log` (Postfix y Amavis).

Las tres rutas están declaradas porque el grupo funcional `zimbra` cubre ambas plataformas. Cada host utiliza las fuentes que existan. La opción `only-future-events=yes` evita importar el histórico al activar cada fuente. Logcollector filtra procesos concretos de SMTP, cola y entrega, además de Amavis/SpamAssassin/ClamAV; excluye `postfix/dkimmilter` y depuración TLS de Submission.

Las reglas OrangeBox `10702`–`10710` se basan en patrones de log confirmados en las muestras de Carbonio/Zimbra. `10702` identifica un RCPT SMTP malicioso ya rechazado; `10703`–`10706` clasifican los veredictos Amavis; `10707`–`10709` clasifican detecciones y estado operativo de ClamAV/Freshclam. `10710` suprime la heurística de PDF cifrado de ClamAV y `20067` suprime el mismo veredicto cuando Amavis lo registra como INFECTED. La validación final de decoders y reglas debe ejecutarse con `wazuh-logtest` en el Manager de producción antes del reinicio. Estos logs no entregan el asunto, el cuerpo, hash ni contenido de adjuntos en las muestras disponibles.

No se recopila `mailbox.log` (`/opt/zimbra/log/mailbox.log` o `/opt/zextras/log/mailbox.log`) en esta fase: contiene actividad del mailbox y puede elevar el volumen con eventos de usuario que no son necesarios para observar el tránsito SMTP.

### Alcance que sí y que no ofrece esta fuente

- Permite analizar eventos Postfix/Amavis que efectivamente se escriban en el log MTA.
- Permite aprovechar las reglas nativas Postfix, incluidas las correlaciones SASL que alimentan la regla OrangeBox `10700`.
- No inspecciona mensajes, cuerpos ni adjuntos.
- No atribuye un asunto ni un hash de adjunto si el log no los registra.
- No se agregan Active Responses nuevos por esta integración.

### Validación tras sincronizar el perfil

1. Confirmar en el agente que el archivo de perfil compartido se sincronizó.
2. Confirmar que Logcollector abrió el archivo MTA que existe en ese servidor.
3. Generar o esperar tráfico SMTP normal y comprobar alertas coincidentes en `alerts.json`. Los eventos de nivel 0 (`Passed CLEAN`) quedan suprimidos y no se conservan porque `logall=no`.
4. Probar muestras anonimizadas `Passed CLEAN`, `Blocked INFECTED`, `Blocked BANNED`, `Passed SPAM` y `clamd ... FOUND` con `wazuh-logtest`.
5. Confirmar en producción que el agente envía las fuentes reales y que `10702`–`10709` disparan los niveles previstos, sin activar Active Response.

La distribución de `agent.conf` es centralizada; no instala paquetes, scripts ni servicios y no requiere reiniciar el agente cuando Wazuh aplica correctamente la nueva configuración.

### Retención y límites de visibilidad

El Manager OrangeBox mantiene `logall=no` y `logall_json=no` deliberadamente. Por tanto, los eventos que no coincidan con una regla no se conservan en `archives.json`; `alerts.json` solo mostrará los eventos que generen alertas.

No habilitar la retención global de todos los logs para depurar correo: el volumen y la información operacional de otros servicios no justifican esa ampliación.

Cobertura que se puede aprovechar una vez que las líneas lleguen al Manager:

- Postfix: decoders y reglas nativas, más la regla OrangeBox `10700` para fuerza bruta SASL.
- ClamAV: Wazuh incluye decoder y reglas nativas (por ejemplo, `52502` para virus detectado, según la versión del ruleset instalada).
- Amavis: las reglas `10703`–`10706` clasifican veredictos reales observados (`CLEAN`, `INFECTED`, `BANNED`, `SPAM`). `CLEAN` se suprime; `INFECTED` es alerta de nivel 14; `BANNED` es revisión de nivel 11; `SPAM` es revisión de nivel 8. Los detalles de Queue-ID, Message-ID, remitente y destinatarios se conservan en `full_log` de las alertas Amavis.
- SMTP RCPT: `10702` detecta subshell/IFS + Base64 + pipe a `sh`/`bash` cuando Postfix registra `NOQUEUE: reject: RCPT`. El evento indica un intento rechazado, no ejecución confirmada. Su `full_log` se omite para no almacenar otra vez payloads de gran tamaño.
- Freshclam: `10709` alerta errores finales o instalación OUTDATED. No alerta por el warning de descarga de `.cdiff` seguido de fallback a descarga completa, porque la muestra no acredita un fallo final.

Para validar la integración, usar `wazuh-logtest` con las líneas originales anonimizadas. No activar `logall_json` global.

## Evidencia de flujo encontrada en logs reales (muestras anonimizadas)

La muestra de Zimbra demuestra que el log MTA contiene suficiente información para reconstruir parte del ciclo SMTP:

1. `postfix/smtpd` registra el peer inmediato EFA y el remitente de sobre en `NOQUEUE: filter`.
2. `postfix/cleanup` registra un Queue ID y el `Message-ID`.
3. `postfix/qmgr` registra el remitente de sobre, tamaño y cantidad de destinatarios.
4. `postfix/smtp` registra el paso hacia el filtro local (puerto 10024) y el Queue ID nuevo indicado por `queued as`.
5. `postfix/amavisd/smtpd` registra la reinyección local.
6. `postfix/lmtp` registra el resultado de entrega por destinatario.

El Queue ID cambia durante la reinyección; el `Message-ID` observado en `cleanup` es un identificador adicional útil para revisar la cadena. No se debe asumir que Queue IDs distintos son mensajes diferentes cuando Postfix indica `queued as`.

La muestra solo identifica como peer inmediato a la IP privada del EFA. No permite atribuir la IP pública original del remitente. Para ello habría que correlacionar con los logs del EFA, si esa fuente ya está disponible en Wazuh.

La muestra de Zimbra solo contiene la reinyección SMTP de Postfix y no un veredicto Amavis. La muestra posterior de Carbonio sí contiene `Passed CLEAN` de Amavis, con Queue-ID, Message-ID, mail_id, remitente, destinatarios y tamaño. No debe inferirse un veredicto de seguridad a partir de `postfix/amavisd/smtpd` por sí solo.

En Carbonio se observó `postfix/dkimmilter/smtpd` emitiendo bloques hexadecimales. El perfil excluye ese proceso para evitar almacenar fragmentos de payload. La muestra entregada no permite confirmar aún qué eventos de cola SMTP normales produce Carbonio en ese mismo archivo; se necesitan líneas filtradas por los procesos permitidos.

### Estado de la implementación

- Recolección: declarada centralmente para Zimbra y Carbonio.
- Postfix: aprovechar primero los decoders y reglas nativas existentes.
- Correlación personalizada de Queue ID / Message-ID: pendiente de validar con `wazuh-logtest` sobre las líneas reales y el decoder de la versión instalada.
- Amavis: reglas `10703`–`10706` para CLEAN/INFECTED/BANNED/SPAM.
- ClamAV/Freshclam: reglas `10707`–`10710` sobre FOUND, la heurística de PDF cifrado y errores/estado de actualización.
- La coincidencia real en el Wazuh Manager de producción queda pendiente de validar con `wazuh-logtest`.
- Sin acceso a asunto, cuerpo ni adjuntos a partir de las muestras actuales.

### Depuración TLS de SMTP Submission

Las muestras de Carbonio incluyen líneas hexadecimales, `read from`, `write to` y `SSL_accept` emitidas por `postfix/submission/smtpd`. El perfil excluye esos eventos de depuración y conserva las líneas de autenticación `sasl_username=`, identificadores de cola y actividad SMTP normal. No se debe ampliar el filtro al nombre genérico `postfix` ni eliminar esta exclusión sin probar primero muestras equivalentes.


## Detecciones añadidas con evidencia de las muestras

- `10702` (nivel 14): payload de shell codificado en un destinatario SMTP, solo cuando Postfix registra `NOQUEUE: reject: RCPT`. Mapea a T1059.004 y T1132.001. No tiene Active Response y omite `full_log` por el tamaño del payload.
- `10703` (nivel 0): nodo base para los veredictos Amavis `Passed/Blocked CLEAN|INFECTED|BANNED|SPAM`; no genera alerta por correo limpio.
- `10704` (nivel 14): Amavis marca `INFECTED`; alerta inmediata de malware, excepto el patrón exacto de PDF cifrado silenciado por `20067`.
- `10705` (nivel 11): Amavis marca `BANNED`; revisión de adjunto prohibido, que no equivale automáticamente a malware.
- `10706` (nivel 8): Amavis marca `SPAM`; revisión antispam. El veredicto puede ser `Passed` o `Blocked`, por lo que la regla no afirma que el mensaje haya sido rechazado.

Las reglas `10702`–`10706` no tienen Active Response. Las alertas Amavis conservan el log de veredicto para que se puedan revisar `Queue-ID`, `queued_as`, `Message-ID`, `mail_id`, remitente y destinatarios. No se registra cuerpo ni contenido del adjunto.


## Logs dedicados de ClamAV y Freshclam

El perfil compartido recoge los logs dedicados de las dos distribuciones:

- Los wildcards `/opt/z*/log/clamd.log` y `/opt/z*/log/freshclam.log` seleccionan los logs del árbol instalado (`/opt/zimbra` o `/opt/zextras`).

La recolección filtra los mensajes de rutina. De ClamAV se conservan `FOUND`, `ERROR` y `WARNING`; de Freshclam, errores, aviso de instalación desactualizada y fallos finales de actualización. Los `SelfCheck: Database status OK` y el fallback recuperable desde un `.cdiff` a descarga completa no generan alertas.

- `10707` (nivel 13): ClamAV encontró una firma (`FOUND`) en un archivo.
- `10710` (nivel 0): `Heuristics.Encrypted.PDF FOUND` queda suprimido; un PDF cifrado puede impedir la inspección, pero no confirma malware.
- `10708` (nivel 9): error o advertencia operativa en `clamd.log`.
- `10709` (nivel 9): error de actualización, fallo final o instalación desactualizada en `freshclam.log`.

Estas reglas no tienen Active Response. `10710` es hija de `10707` y suprime únicamente esa heurística exacta. `20067` es hija de `10704` y suprime únicamente el veredicto Amavis `Blocked INFECTED (Heuristics.Encrypted.PDF)`. Las demás firmas `FOUND` y los demás veredictos `INFECTED` mantienen su severidad crítica. El evento de ClamAV se puede correlacionar con el veredicto Amavis y sus Queue-ID/Message-ID cuando ambos registros estén disponibles.
