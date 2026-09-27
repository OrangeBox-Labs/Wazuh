# `ossec.conf`

## Persistencia de alertas

La configuración de referencia utiliza:

```xml
<jsonout_output>yes</jsonout_output>
<alerts_log>no</alerts_log>
...
<alerts>
  <log_alert_level>5</log_alert_level>
  <email_alert_level>16</email_alert_level>
</alerts>
```

### Motivo

`alerts.json` es la fuente estructurada utilizada por el pipeline de indexación, reportes y las integraciones OrangeBox. Mantener además `alerts.log` duplica el mismo volumen de eventos en formato de texto.

Por eso el repositorio público conserva JSON y deshabilita la salida plaintext.

El umbral `log_alert_level=5` reduce la persistencia de telemetría de severidad baja sin elevar artificialmente los niveles de las reglas. Las reglas auxiliares de correlación pueden permanecer en niveles bajos cuando son necesarias para construir una detección posterior; las alertas de seguridad finales conservan sus niveles OrangeBox.

### Impacto

- Las alertas de nivel 5 o superior continúan disponibles en `alerts.json`.
- Las señales de nivel inferior pueden seguir participando en el motor de reglas y correlaciones aunque no se persistan en `alerts.json`, siempre que la cadena de reglas lo requiera.
- Los reportes de seguridad se basan en los eventos persistidos que el propio reporte clasifica como relevantes.
- No se debe elevar artificialmente el nivel de las reglas auxiliares solo para hacerlas coincidir con el umbral.

## Fuente de correo nativa

```xml
<email_log_source>alerts.json</email_log_source>
<email_alert_level>16</email_alert_level>
```

La fuente JSON mantiene coherencia con la salida principal del Manager. El correo nativo se deja en nivel 16 porque las alertas OrangeBox se gestionan mediante la integración HTML propia y no queremos duplicar el mismo evento por dos caminos.

## Integración de correo OrangeBox

La integración se ejecuta con:

```xml
<integration>
  <name>custom-orangebox-email.py</name>
  <hook_url>TU_EMAIL</hook_url>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

El nivel 12 significa que solo las alertas de ese nivel o superior son entregadas a esta integración. Las reglas OrangeBox que requieren correo inmediato están por encima de este umbral.

## Lecciones operacionales

### No bloquear `wazuh-integratord` con la ventana de agrupación

El integrador ejecuta la integración con `stdout/stderr` conectados a un pipe y espera su cierre. El proceso hijo utilizado para la agrupación de 10 minutos debe cerrar esa herencia antes de dormir.

La implementación actual redirige:

```text
stdin  -> /dev/null
stdout -> /dev/null
stderr -> /dev/null
```

antes de iniciar `sleep(600)`.

**Motivo:** sin este desacople, un solo proceso hijo podía mantener abierto el pipe durante toda la ventana de agrupación y retrasar alertas posteriores, incluidas las alertas inmediatas de SSH, SU y SUDO.

## Entrega de correo resiliente

`custom-orangebox-email.py` entrega los mensajes mediante:

```text
/usr/sbin/sendmail -t -i
```

en lugar de abrir una conexión SMTP directa contra `localhost:25`.

### Motivo

Una conexión directa con `smtplib.SMTP("localhost")` puede fallar con `ECONNREFUSED` si Postfix está detenido o reiniciándose justo en el momento del evento.

La vía `sendmail` entrega el mensaje al `maildrop` local de Postfix, de modo que el MTA puede procesarlo posteriormente cuando vuelva a estar activo.

### Resultado esperado

```text
Wazuh
  |
  v
custom-orangebox-email.py
  |
  v
Postfix maildrop
  |
  +-- Postfix activo  -> cola -> entrega
  |
  +-- Postfix detenido -> mensaje persistente
                           |
                           v
                      Postfix inicia
                           |
                           v
                        pickup
                           |
                           v
                        entrega
```

Esta arquitectura evita perder una alerta de correo por una caída temporal del MTA.

## Validación recomendada

Antes de reiniciar el Manager después de cambios en `ossec.conf`, validar la configuración:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Después, probar las cadenas críticas con:

```bash
/var/ossec/bin/wazuh-logtest
```

Las pruebas mínimas de regresión deben incluir:

- SSH exitoso -> `10001`.
- `su -> root` -> `10004`.
- `sudo -> root` sin excepción -> `10005`.
- una señal auxiliar de correlación que dependa de una regla de bajo nivel.
- entrega de correo con Postfix activo y con Postfix temporalmente detenido.

## Nota de publicación

Este archivo documenta decisiones de arquitectura y el motivo de los cambios. Los valores de infraestructura del repositorio público permanecen sanitizados y deben adaptarse al entorno de cada organización.
