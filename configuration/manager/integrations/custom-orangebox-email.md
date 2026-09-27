# `custom-orangebox-email.py`

## Qué hace

Es la integración de correo HTML de OrangeBox para Wazuh.

Wazuh entrega la alerta en JSON y este script decide si:

- la envía inmediatamente;
- la agrupa durante una ventana de 10 minutos;
- evita duplicados;
- conserva el detalle FIM;
- genera el correo HTML;
- lo entrega al SMTP local.

La razón de tener un script propio es que el correo nativo de Wazuh no entrega el formato ni el comportamiento de agrupación que necesitamos.

## Envío inmediato

Las reglas consideradas inmediatas se definen explícitamente por ID:

- `5715` - login SSH exitoso nativo.
- `10001` - login SSH exitoso OrangeBox.
- `10004` - `su` hacia root.
- `10005` - `sudo` hacia root sin excepción válida.
- `10008` - sudo exitoso.
- `10009` - sudo exitoso.

No se utiliza el grupo `privilege_escalation_root` como criterio genérico de inmediatez. Esto evita que una regla nueva quede inmediata simplemente por compartir una categoría.

Las reglas `10025`, `10026`, `10453` y `10454` permanecen fuera del correo individual porque tienen Active Response `firewall-drop`. `10455` tampoco genera correo individual.

## Deduplicación de 5715 / 10001

`5715` y `10001` pueden representar el mismo login SSH.

La política efectiva es:

```text
máximo 1 correo
por agente + IP origen + día
```

Cuando journald no entrega `srcip`, primero se intenta recuperar la IP directamente desde `full_log` en mensajes `Accepted ... from <IP> port <N>`. Si tampoco existe una IP utilizable, se utiliza la identidad/fingerprint SSH cuando existe.

La implementación usa marcadores individuales creados con `O_CREAT | O_EXCL`. Esto evita que varias ejecuciones simultáneas del integrador ganen la carrera para enviar el mismo primer correo.

También se consulta el estado JSON histórico `ssh_notifications.json` para conservar compatibilidad con la implementación anterior.

Esto **no elimina las alertas de Wazuh**. Un segundo o tercer login desde la misma IP durante el mismo día permanece en `alerts.json`, pero no genera otro correo SSH.

Si falla el mecanismo de estado, la integración opera fail-open y registra el error en `/var/ossec/logs/integrations.log`; la prioridad es no perder alertas.

La deduplicación por IP se implementa mediante marcadores individuales atómicos (`O_CREAT | O_EXCL`), evitando carreras entre procesos separados del integrador. El marcador incluye agente, IP y fecha. La regla de negocio sigue siendo una sola notificación SSH por agente + IP + día.

## Agrupación de alertas

### `10005` y aplicaciones automatizadas

`10005` permanece en `IMMEDIATE_RULES` porque representa un `sudo -> root` que no fue validado por una excepción operacional. Un servidor cPanel con WP Toolkit debe eliminar del flujo los comandos conocidos mediante reglas `level 0` por perfil; cualquier `10005` restante se considera no autorizado y se envía inmediatamente.

La alerta Wazuh no se elimina ni se retrasa en `alerts.json`: únicamente se retrasa/agruppa el correo.

Las alertas que no son inmediatas se agrupan durante `600` segundos.

La clave del buffer es:

```text
agent_id + rule_id
```

Esto evita mezclar cosas que no tienen relación.

Por ejemplo:

```text
agente A + regla 10410
agente A + regla 10030
```

usan buffers diferentes.

También quedan separados dos agentes aunque tengan la misma regla.

### Por qué existe el proceso hijo

El primer evento crea el buffer y genera un proceso hijo que espera los 10 minutos.

El proceso principal termina inmediatamente. El hijo desacopla `stdin`, `stdout` y `stderr` mediante `/dev/null` antes de dormir. Esto es **obligatorio** porque `wazuh-integratord` ejecuta la integración con esos descriptores conectados a un pipe y espera EOF; si el hijo heredara el pipe, la ventana de 10 minutos bloquearía el procesamiento de alertas posteriores.

Además, la creación del buffer usa `O_EXCL`. Así, cuando llegan muchas alertas simultáneamente, solamente un proceso puede declararse dueño del buffer.

Esto corrige el problema clásico de:

```text
25 alertas simultáneas
        ↓
25 procesos creen que son el primero
        ↓
25 correos
```

## Protección contra duplicados

Cada evento conserva el `alert_id` de Wazuh.

Si el mismo evento vuelve a entrar al buffer, no se agrega nuevamente.

No usamos la ruta del archivo como identificador porque el mismo archivo puede generar eventos legítimos distintos.

## FIM: conservar la evidencia completa

El script conserva el objeto `syscheck` completo.

Además mantiene algunos campos individuales por compatibilidad:

- ruta;
- diff;
- tamaño;
- propietario;
- hashes;
- atributos modificados.

Esto se hizo porque una versión anterior guardaba solamente algunos campos y podía perder información entregada por Wazuh.

Para seguridad esto importa bastante: cuando estamos investigando un cambio de archivo, queremos ver la evidencia que Wazuh realmente recibió, no una versión recortada porque al script le dio flojera guardarla. 😎

También se conserva el JSON completo de la alerta dentro del evento. Eso permite recuperar información adicional en el futuro sin rediseñar nuevamente el buffer.

## HTML

El correo se genera directamente en HTML y contiene:

- nivel de alerta;
- regla;
- agente;
- origen/ubicación;
- grupos;
- cantidad de eventos;
- detalles FIM;
- hashes disponibles;
- diff;
- logs crudos;
- enlace directo al Dashboard de Wazuh.

Los datos variables pasan por `html.escape()` antes de insertarse en el HTML. Esto evita que contenido proveniente del log o del diff termine interpretándose como HTML.

## Niveles visuales

El encabezado clasifica visualmente el correo según el nivel máximo:

- `>= 12` → CRITICO
- `>= 7` → ADVERTENCIA
- menor → INFORMACION

No cambia el nivel real de Wazuh; solamente cambia la presentación del correo.

## Entrega de correo resiliente

El script **no abre una conexión SMTP TCP contra `localhost:25`**.

Entrega el mensaje mediante:

```text
/usr/sbin/sendmail -t -i
```

En Postfix, esta vía coloca el mensaje en el `maildrop` local. Por eso una caída temporal del daemon Postfix no provoca `ECONNREFUSED` ni descarta la alerta: el mensaje queda persistente para que Postfix lo procese cuando vuelva a estar activo.

### Motivo del cambio

La implementación anterior usaba `smtplib.SMTP("localhost")`. Si Postfix estaba detenido o reiniciándose justo en el instante del envío, Python recibía `Connection refused` y la alerta no tenía una segunda oportunidad.

El cambio mueve la responsabilidad de cola y reintento al MTA, donde corresponde.

### Prueba de resiliencia

Se validó operacionalmente con Postfix completamente detenido:

```text
custom-orangebox-email.py
        -> /usr/sbin/sendmail
        -> maildrop Postfix
        -> mensaje queda en cola

Postfix vuelve a iniciar
        -> pickup
        -> queue
        -> entrega SMTP
```

La prueba real dejó un mensaje en cola con Postfix detenido y la cola quedó vacía después de volver a iniciar el servicio.

El remitente usado por el HTML es:

```text
Wazuh SOC <TU_EMAIL>
```

## Integración con `ossec.conf`

`ossec.conf` llama esta integración con:

- formato `json`;
- nivel `12`;
- destinatario configurado en `hook_url`.

El correo nativo de Wazuh queda con `email_alert_level=16`, evitando que una misma alerta termine saliendo por dos caminos.

## Manejo de errores

Si falla la deduplicación SSH, el script prefiere **enviar la alerta** antes que perderla.

Los errores se escriben en:

```text
/var/ossec/logs/integrations.log
```

La filosofía es simple: un mecanismo de control de duplicados nunca debe convertirse en un mecanismo para perder alertas.

## Archivos utilizados

```text
/tmp/wazuh_email_buffer/
```

Buffers temporales de agrupación.

```text
/var/ossec/logs/orangebox_email_state/ssh_notifications.json
```

Estado persistente de deduplicación SSH.

El estado SSH basado en marcadores se conserva aproximadamente 7 días. La implementación usa archivos creados atómicamente con `O_CREAT | O_EXCL`; el JSON histórico se mantiene como compatibilidad.

## Decisiones que no deben cambiarse a la ligera

### No usar `sleep()` en el proceso principal

Bloquear el proceso de integración puede afectar el procesamiento de alertas.

### No deduplicar todo por regla

Dos alertas iguales en texto pueden representar incidentes distintos. La deduplicación agresiva puede esconder evidencia.

### No deduplicar FIM por ruta

Un mismo archivo puede ser creado, modificado y eliminado. Son eventos distintos y deben conservarse.

### No confiar en que `full_log` sea seguro para HTML

Los logs son datos externos. Siempre deben escaparse antes de insertarlos en el correo.

## Dependencias

- Python 3.
- Wazuh Manager.
- SMTP local en `localhost`.
- Permisos para escribir en `/tmp/wazuh_email_buffer` y `/var/ossec/logs/orangebox_email_state`.
- Integración JSON configurada en `ossec.conf`.

## Nota

Este script forma parte de la política de alertamiento OrangeBox. Las reglas deciden **qué pasó**; este script decide **cómo avisarnos sin convertir el correo en una ametralladora de spam**.
