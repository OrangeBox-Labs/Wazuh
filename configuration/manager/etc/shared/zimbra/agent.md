# Perfil FIM Zimbra / Carbonio CE

Este perfil agrupa Zimbra y Carbonio CE como una misma familia operacional para FIM y para la política validada de `sudo -> root`. Zimbra utiliza `/opt/zimbra`; Carbonio CE utiliza `/opt/zextras`.

## Identificación y fuente de verdad

La pertenencia al grupo Wazuh `zimbra` es la fuente de verdad. `update-orangebox-zimbra-agents.sh` consulta ese grupo y genera la CDB dinámica `orangebox-zimbra-agents` con FQDN y hostname corto. El archivo se mantiene en `/var/ossec/etc/lists/` del Manager y no se versiona porque se genera localmente.

La etiqueta `orangebox.profile=zimbra` identifica el perfil en los eventos. La regla `110100` consulta `orangebox-zimbra-agents`; el perfil por sí solo no autoriza comandos SUDO.

## Alcance FIM base

El `agent.conf` incluye controles base para temporales, SSH, identidad, SUDO, PAM, SYSTEMD, CRON, persistencia, red, certificados y firewall. El límite FIM es 175000 entradas y `alert_new_files` permanece activo.

Los archivos sensibles como `shadow`, `gshadow` y claves privadas se monitorizan sin almacenar diffs cuando el contenido podría exponer secretos.

## Rutas específicas del producto

### Temporales internos de Zimbra/Carbonio (excluidos)

No se monitorizan con FIM:

```text
/opt/zimbra/data/tmp
/opt/zextras/data/tmp
```

Estas rutas contienen blobs, cachés y archivos de procesamiento efímeros. Los eventos FIM de esos archivos no permiten identificar de forma fiable el mensaje, remitente ni conexión SMTP que los originó. Por este motivo, quedan fuera de las reglas 10420/10421 y del análisis YARA genérico.

La exclusión es deliberada y no afecta al monitoreo de configuración, certificados, binarios privilegiados ni webapps.

### Jetty / webapps

Se vigilan en tiempo real únicamente extensiones relacionadas con ejecución y despliegue:

```text
/opt/zimbra/jetty/webapps
/opt/zextras/jetty/webapps
```

El filtro se limita a `jsp`, `jspx`, `war` y `class`; no se recorre todo el árbol del producto.

### Configuración y certificados

Se vigilan en tiempo real con Who-Data:

```text
/opt/zimbra/conf
/opt/zextras/conf
/opt/zimbra/ssl
/opt/zextras/ssl
```

Los árboles SSL usan `nodiff`: el evento y su atribución se conservan, pero no se copia el contenido de certificados o claves a las alertas.

### Binarios privilegiados

El perfil limita la vigilancia de binarios a los comandos utilizados por la allowlist `sudo -> root`:

- `zmstat-fd`, `zmqstat`, `zmmtastatus` y `zmmailboxdmgr` bajo `libexec`;
- `postfix`, `postalias`, `qshape.pl`, `postconf`, `postsuper` y `postcat` bajo `common/sbin`.

Se vigilan en tiempo real con Who-Data y filtros `restrict`. No se monitoriza completo `/opt/zimbra` ni `/opt/zextras`.

## Política SUDO

La regla `10005` es el detector general de `sudo -> root`. La regla `110100` solo lleva el evento a nivel 0 cuando se cumplen simultáneamente:

1. el hostname pertenece al grupo Wazuh `zimbra` y está presente en la CDB `orangebox-zimbra-agents`;
2. el ejecutable y sus argumentos pertenecen a la allowlist operacional de Zimbra/Carbonio.

Cualquier otro comando o servidor sigue generando `10005`. La pertenencia al grupo por sí sola no autoriza comandos.

## Dependencias

- Grupo Wazuh `zimbra` y CDB dinámica `orangebox-zimbra-agents` sincronizada.
- Wazuh Agent / Syscheck.
- Who-Data/Audit habilitado para las rutas donde se requiere atribución.
- Reglas `orangebox-auth.xml` y `orangebox-hardening.xml` en el Manager.

## Validación

1. Confirmar la pertenencia al grupo `zimbra`, la etiqueta del perfil y la CDB `orangebox-zimbra-agents`.
2. Ejecutar `update-orangebox-zimbra-agents.sh` y validar la configuración del Manager con `wazuh-analysisd -t`.
3. En laboratorio, crear un archivo temporal y una muestra JSP inocua bajo webapps; verificar los eventos FIM.
4. Modificar una configuración no sensible en `/opt/zimbra/conf` o `/opt/zextras/conf` y revisar Who-Data.
5. Probar `110100` con un comando permitido, el mismo comando fuera del perfil y un comando no permitido.

No realizar estas pruebas con comandos ejecutables ni archivos de aplicación reales en producción.

## Recolección de correo mediante el agente Wazuh existente

El bloque `localfile` del perfil compartido recoge únicamente el log MTA consolidado de la plataforma:

- Zimbra: `/var/log/maillog` y `/var/log/zimbra.log`; la fuente efectiva depende del enrutamiento syslog del servidor.
- Carbonio CE: `/var/log/carbonio.log`, fuente syslog que contiene actividad Postfix y veredictos Amavis.

Las tres rutas se declaran porque el grupo funcional agrupa Zimbra y Carbonio; cada host utiliza los archivos que realmente existen. `only-future-events=yes` limita la lectura a eventos nuevos desde la activación y evita importar el histórico.

Además, los wildcards `/opt/z*/log/clamd.log` y `/opt/z*/log/freshclam.log` seleccionan los logs de ClamAV/Freshclam del árbol de producto instalado (`/opt/zimbra` o `/opt/zextras`) y los filtran: `clamd` solo `FOUND`/`ERROR`/`WARNING`; `freshclam` solo errores, instalaciones desactualizadas o fallos finales de actualización. SelfCheck OK y los fallbacks incrementales recuperables quedan fuera.

No se incluyen los logs de mailbox ni el árbol temporal de Amavis: no son necesarios para esta primera etapa de monitoreo SMTP y podrían exponer o indexar datos de usuario sin aportar una identificación fiable del mensaje.

Esta recolección utiliza Logcollector del agente Wazuh ya instalado. No se agregan paquetes, scripts, servicios, comandos remotos ni cambios locales en `ossec.conf`. La configuración se distribuye desde el Manager mediante este perfil centralizado.

Las reglas `10702`–`10710` se basan en patrones observados en logs reales: intento shell codificado en RCPT ya rechazado, veredictos Amavis CLEAN/INFECTED/BANNED/SPAM, detección ClamAV FOUND y errores/estado de Freshclam. La excepción `20067` silencia únicamente el veredicto Amavis `Blocked INFECTED (Heuristics.Encrypted.PDF)`; `10710` silencia la misma heurística en `clamd.log`. La excepción FIM `20068` cubre exclusivamente los temporales `scantem/clamav-*.tmp` del escáner; hashes conocidos fuera de esa ruta siguen alertando. Ninguna instala componentes locales ni activa Active Response. La validación de coincidencia en el motor Wazuh de producción se debe completar con `wazuh-logtest`.
Las fuentes usan un filtro Logcollector PCRE2 para aceptar procesos concretos de SMTP, cola y entrega de Postfix, además de `amavis`, `spamd`, `clamd` y `freshclam`. No se acepta el nombre genérico `postfix`: se excluyen los volcados de `dkimmilter` y la depuración TLS de Submission (bloques hexadecimales, `read from`, `write to`, `SSL_accept` y session tickets).

### Protección frente a volcados de DKIM

En Carbonio se observó que `postfix/dkimmilter/smtpd` escribe bloques hexadecimales con representación ASCII. Esos registros pueden contener fragmentos del flujo del mensaje y no deben enviarse al Manager.

Por eso el filtro del perfil no acepta el proceso genérico `postfix`: permite únicamente procesos concretos de SMTP, cola, entrega y reinyección. Además, descarta explícitamente `postfix/dkimmilter/`. También excluye líneas de `postfix-script`, que son mensajes de estado y no eventos de tránsito del correo.

La prueba `tests/test_zimbra_mail_log_sources.py` incluye muestras sintéticas de eventos SMTP/cola y de los volcados DKIM para impedir que una ampliación accidental vuelva a recogerlos.

### Exclusión de depuración TLS de Submission

Las líneas de depuración TLS de `postfix/submission/smtpd` y `postfix/smtps/smtpd` pueden incluir volcados hexadecimales, lecturas/escrituras de socket y negociación TLS. El perfil las descarta mediante `ignore`, pero conserva eventos de negocio y autenticación como `client=`, `sasl_username=`, Queue ID y `disconnect`.

No se recopilan volcados DKIM (`postfix/dkimmilter`). Esta exclusión se prueba con muestras del host para evitar almacenar datos de transporte y ruido de depuración.
