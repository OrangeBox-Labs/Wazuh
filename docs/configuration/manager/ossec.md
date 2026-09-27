# `ossec.conf`

## Qué hace

Es la configuración principal del Wazuh Manager de OrangeBox.

Aquí no viven las reglas personalizadas ni la configuración específica de cada agente. Este archivo define el comportamiento general del Manager: recepción de eventos, FIM global, inventario, SCA, vulnerabilidades, Active Response, fuentes locales y la integración de correo.

La arquitectura buscada es:

```text
EVENTO
  ↓
DETECCION / CORRELACION
  ↓
ALERTA
  ├── correo HTML
  └── Active Response cuando corresponde
```

## 1. Salida de alertas

Se mantiene `alerts.json` porque la integración `custom-orangebox-email.py` necesita recibir las alertas en JSON.

`alerts.log` también permanece habilitado para diagnóstico e integraciones.

No se registra absolutamente todo con `logall` / `logall_json`. No necesitamos convertir el Manager en una aspiradora de logs.

## 2. Correo

El correo nativo de Wazuh queda con umbral `16`.

La razón es evitar que una alerta personalizada de nivel 12/13 salga dos veces: una por el mecanismo nativo y otra por nuestro HTML.

El envío principal lo hace:

```text
custom-orangebox-email.py
```

La integración personalizada recibe JSON y se encarga del formato, agrupación y deduplicación.

## 3. Agentes desconectados

Se considera desconectado un agente que lleva más de `10m` sin conexión.

`agents_disconnection_alert_time=0` hace que la alerta se genere inmediatamente al alcanzar ese umbral.

## 4. Whitelist global

La whitelist global queda reservada para infraestructura necesaria para el funcionamiento general del Manager:

- localhost;
- Wazuh Manager;
- servidor de monitoreo/Zabbix;
- Zabbix Proxy.

**Reverse proxies y BackupPC no se incluyen en la whitelist global.** Sus excepciones son específicas de cada detección y se gestionan mediante CDB:

- `orangebox-backuppc` para SSH;
- `orangebox-web-auth-proxies` para brute force web;
- `orangebox-web-discovery-proxies` para discovery web.

Así una excepción operacional no silencia otras categorías de seguridad del Manager.

## 5. Recepción de agentes

Los agentes utilizan TCP/1514 mediante la conexión segura de Wazuh.

La cola está configurada en `131072` para absorber ráfagas de eventos sin que el Manager se atragante ante un pico puntual.

## 6. Rootcheck

Rootcheck permanece activo y revisa archivos, troyanos, dispositivos, sistema, procesos, puertos e interfaces.

Se ejecuta cada `43200` segundos, es decir, dos veces al día.

Se excluyen NFS y directorios con grandes cantidades de archivos dinámicos, como capas de Docker/containerd, para evitar trabajo inútil y ruido.

Rootcheck no es el detector principal de malware. Trabaja junto con FIM, reglas, SCA y vulnerability detection.

## 7. CIS-CAT y OSQuery

Ambos están deshabilitados actualmente.

No se eliminan de la configuración porque pueden activarse posteriormente si aparece una necesidad concreta.

SCA cubre actualmente la evaluación de configuración de seguridad.

## 8. Syscollector

Se mantiene activo con una frecuencia de `1h`.

Recoge:

- hardware;
- sistema operativo;
- red;
- paquetes;
- puertos;
- procesos.

Este inventario también sirve como base para otras capacidades de Wazuh, incluida la detección de vulnerabilidades.

La sincronización está limitada a `10 EPS` para evitar picos innecesarios.

## 9. SCA

Security Configuration Assessment está habilitado, comienza al iniciar y vuelve a ejecutar análisis cada `12h`.

No se mezcla su función con las reglas FIM: SCA evalúa configuración; FIM observa cambios.

## 10. Vulnerability Detection

Está habilitado y utiliza el inventario de software de los agentes.

El feed se actualiza cada hora.

Las reglas personalizadas pueden posteriormente elevar determinados resultados, por ejemplo vulnerabilidades críticas, al nivel de alerta que necesita el sistema de correo.

## 11. Indexer

El Manager utiliza el Wazuh Indexer local mediante HTTPS en:

```text
https://IP_DE_INDEXER:9200
```

La conexión utiliza los certificados definidos bajo `/etc/filebeat/certs/`.

## 12. FIM global

FIM está activo con:

- análisis completo cada `12h`;
- análisis al inicio;
- alertas de archivos nuevos;
- sincronización cada `5m`;
- máximo global de `50 EPS`.

El `auto_ignore` está desactivado. Para esta instalación queremos conservar visibilidad sobre archivos críticos aunque se modifiquen repetidamente.

Se excluyen archivos dinámicos, logs, swaps y pseudo-filesystems para evitar ruido.

También se evita generar diff de `/etc/ssl/private.key`, porque no queremos mandar material sensible al sistema de alertas.

La configuración detallada de rutas de los agentes vive en `configuration/agents/`, no aquí.

## 13. Active Response

Aquí se declaran los comandos disponibles. Las reglas determinan cuándo se ejecutan.

Entre ellos están:

- `disable-account`;
- `restart-wazuh`;
- `firewall-drop`;
- `host-deny`;
- `route-null`;
- comandos equivalentes para Windows.

No todo incidente debe bloquearse automáticamente. Por ejemplo, un cambio local de archivo puede no tener una IP de origen que tenga sentido bloquear.

## 14. Brute force SSH

La configuración actual aplica `firewall-drop` a la regla nativa `5720` durante `180` segundos.

No bloqueamos por un solo fallo. Primero necesitamos la correlación de múltiples fallos.

### Importante: 10006

La documentación de reglas OrangeBox debe considerarse la referencia para la correlación real utilizada actualmente.

La regla `10006` fue validada con la secuencia efectiva `5763 -> 10001` y `same_source_ip`.

Por eso no hay que cambiar esta sección de `ossec.conf` solamente porque el comentario histórico mencione `5720`/`5715`. El Active Response y la regla OrangeBox son capas distintas y deben mantenerse alineadas cuando se cambie la política.

## 15. Brute force SSH seguido de login exitoso

`10006` ejecuta `firewall-drop` durante `86400` segundos, es decir, 24 horas.

La lógica es mucho más agresiva que la de brute force simple:

```text
muchos fallos
     ↓
login exitoso desde la misma IP
     ↓
posible intrusión exitosa
     ↓
bloqueo 24h
```

Esto se diseñó para detectar el escenario que realmente nos interesa: no solamente que alguien esté golpeando SSH, sino que eventualmente consiguió entrar.

## 16. Reconocimiento web de archivos sensibles

La regla `10026` también usa `firewall-drop` durante 24 horas.

Se aplica a múltiples intentos contra rutas sensibles como `.env`, credenciales de AWS/GCloud/OCI, `wp-config.php` y rutas equivalentes detectadas por las reglas web.

No se confía en User-Agent para permitir crawlers. Se puede falsificar demasiado fácilmente.

## 16B. Port scan OrangeBox

La regla OrangeBox `10453` ejecuta `firewall-drop` localmente cuando se detectan 12 intentos TCP SYN en 90 segundos desde la misma IP hacia diferentes puertos destino.

El bloqueo inicial es de:

```text
3600 segundos = 1 hora
```

El Active Response recibe `srcip` y aplica el bloqueo local en el agente donde se generó la alerta.

La duración inicial se mantiene en una hora para permitir una respuesta automática sin convertir la primera detección en un bloqueo permanente. La reincidencia se evaluará posteriormente mediante los mecanismos de repetición de Active Response.

## 16C. Flood y DoS de red

Las señales de volumen utilizan la misma fuente `/var/log/orangebox-firewall.log` y la misma regla precursora `10450`.

### 10454 - SYN flood desde una misma IP

Se requieren 60 TCP SYN en 10 segundos, desde la misma IP y hacia el mismo puerto destino.

`10454` tiene Active Response `firewall-drop` durante 3600 segundos.

### 10455 - posible DoS distribuido

Se requieren 200 IPs origen diferentes en 10 segundos hacia el mismo puerto destino.

No se aplica Active Response automáticamente a `10455`, porque un evento individual no identifica una única IP que represente al conjunto del ataque.

Los elementos `same_srcip`, `different_srcip` y `same_dstport` son filtros de correlación soportados por Wazuh y se usan junto con `frequency` y `timeframe`. 

Los umbrales son valores iniciales de OrangeBox y deben validarse contra el comportamiento real de cada servidor antes de endurecer la respuesta automática.

## 17. Comandos locales

El Manager ejecuta periódicamente:

```text
df -P
netstat listening ports
last -n 20
```

Cada uno se ejecuta cada `360` segundos.

El objetivo es alimentar a Wazuh con información básica del propio Manager sin depender exclusivamente de logs externos.

## 18. Ruleset

Se cargan las reglas y decoders oficiales de Wazuh y además los personalizados bajo:

```text
/etc/decoders
/etc/rules
```

No se reemplaza el ruleset oficial. OrangeBox agrega sus propias reglas encima de la base nativa.

Esto es importante porque las reglas OrangeBox dependen de SIDs nativos como `550`, `553`, `5715`, `5763`, etc.

## 19. Rule Test

`rule_test` está habilitado para poder utilizar `wazuh-logtest` durante el desarrollo y validación del ruleset.

Esto fue especialmente importante durante la construcción de las reglas SSH y FIM: las expresiones se prueban con eventos reales antes de incorporarlas a producción.

## 20. Authd

El registro de agentes utiliza el puerto `1515` y requiere password.

`use_source_ip=no` evita confiar automáticamente en la IP de origen como identidad del agente, algo especialmente importante cuando existen NAT o redes WAN.

Se definen suites criptográficas explícitas, pero **no se documenta esto como "TLS 1.3 obligatorio"**. La compatibilidad real depende de la versión de Wazuh/OpenSSL.

`ssl_verify_host=no` se mantiene deliberadamente.

En Wazuh, esta opción valida el host de origen del agente contra el nombre/IP presente en su certificado y **solo entra en juego cuando se configura una CA para verificar certificados de agentes mediante `ssl_agent_ca`**. Activarla no es un endurecimiento genérico del TLS: forma parte de una arquitectura distinta de enrolamiento basada en certificados por agente.

Nuestra configuración actual utiliza enrolamiento mediante password compartida y no define `ssl_agent_ca`. Por eso no se cambia `ssl_verify_host` de forma aislada: hacerlo no implementaría una validación de identidad coherente y podría romper agentes cuando posteriormente se introduzca validación por certificado sin haber preparado la PKI correspondiente.

Cuando se diseñe esa etapa, debe implementarse completa: CA, certificados de agente, claves en los endpoints y validación de hostname/IP coherente con la identidad real de cada agente.

## 21. Cluster

El cluster está deshabilitado.

No hay razón para mantener componentes activos de una arquitectura que actualmente no usamos.

## 22. Fuentes locales del Manager

La segunda sección `<ossec_config>` incorpora eventos locales mediante:

- systemd journal;
- auditd;
- Active Response log.

Esto permite que las propias acciones del Manager y las acciones de contención vuelvan a quedar visibles para Wazuh.

## Plantilla para Agent Groups

El framework del Wazuh Manager utiliza:

```text
/var/ossec/etc/shared/agent-template.conf
```

como plantilla al crear un nuevo Agent Group. El código de Wazuh 4.14.7 crea el directorio del grupo y copia esta plantilla como `agent.conf`. Si el archivo no existe, la creación del grupo falla con un error de lectura.

La plantilla versionada por OrangeBox se encuentra en:

```text
configuration/manager/agent-template.conf
```

Contenido esperado en runtime:

```xml
<agent_config>
</agent_config>
```

No debe contener la política de un perfil concreto. Su única función es permitir la creación limpia de grupos; la configuración específica queda en `/var/ossec/etc/shared/<grupo>/agent.conf`.

Antes de utilizar el Dashboard para crear grupos, validar:

```bash
ls -l /var/ossec/etc/shared/agent-template.conf
/var/ossec/bin/agent_groups -l
```

## 23. Integración HTML OrangeBox

La integración:

```text
custom-orangebox-email.py
```

recibe alertas JSON desde nivel `12` y genera el correo HTML corporativo.

El diseño de esta separación es intencional:

```text
ossec.conf
   ↓
Wazuh detecta y correlaciona
   ↓
regla >= 12
   ↓
custom-orangebox-email.py
   ↓
correo HTML
```

El Manager no necesita saber cómo construir el HTML. Y el script de correo no necesita saber cómo detectar un ataque.

Cada cosa en su corral.

## Decisiones generales

### No meter las reglas aquí

Las reglas tienen su propio ciclo de pruebas y deben poder cambiar sin convertir `ossec.conf` en una ensalada.

### No depender solamente del correo nativo

Necesitamos agrupación, deduplicación SSH, detalle FIM completo y formato HTML. Eso pertenece a la integración personalizada.

### No bloquear todo automáticamente

Active Response se usa donde existe suficiente confianza en la detección y una IP de origen que pueda bloquearse.

### No prometer configuraciones criptográficas que no comprobamos

Especialmente en `authd`: se documenta lo que realmente está configurado, no lo que nos gustaría creer que está configurado.

## Dependencias principales

- Wazuh Manager.
- Wazuh Indexer.
- Wazuh Agent para las fuentes remotas.
- reglas y decoders nativos de Wazuh.
- reglas OrangeBox bajo `/var/ossec/etc/rules`.
- integración `custom-orangebox-email.py`.
- auditd y systemd journal en el Manager.


## CDB de perfiles de agentes

El `<ruleset>` incluye la lista:

```text
etc/lists/orangebox-agent-profiles
```

Esta CDB relaciona el `hostname` predecodificado del evento con un perfil funcional mediante `match_key_value`.

Perfiles actuales:

```text
cpanel
zimbra
```

`zimbra` representa la política funcional compartida por Zimbra y Carbonio CE.

Las excepciones de aplicaciones utilizan esta CDB para reducir falsos positivos en el ruleset antes de que lleguen a la integración de correo.

Después de modificar la CDB se debe reiniciar el Manager para que el motor cargue la nueva lista.