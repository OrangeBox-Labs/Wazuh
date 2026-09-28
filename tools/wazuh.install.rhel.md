# wazuh.install.rhel.sh

Script idempotente para instalar y mantener Wazuh Agent y el logging de red OrangeBox.

## Compatibilidad

Objetivo:

- CentOS 6, 7 y 8
- AlmaLinux 8, 9 y 10

Para sistemas sin systemd utiliza SysV init.

## Backend de logging

El script detecta la versión major de Enterprise Linux y selecciona el backend correspondiente:

### EL6

```text
iptables -> rsyslog -> /var/log/orangebox-firewall.log -> Wazuh
```

En EL6 se configuran:

- rsyslog;
- `/var/log/orangebox-firewall.log`;
- filtro exclusivo para `ORANGEBOX-FW:`;
- logrotate en `/etc/logrotate.d/orangebox-firewall`.

El script valida que el evento de prueba llegue al log dedicado y no a `/var/log/messages`.

### EL7+

```text
iptables -> journald -> Wazuh
```

En EL7 y superiores no se modifica la configuración de rsyslog ni se crea el log dedicado de OrangeBox.

El script valida que journald esté disponible y que un evento de prueba con el prefijo `ORANGEBOX-FW:` quede registrado.

Esto evita duplicar la cadena de logging en sistemas modernos, donde el agente Wazuh puede consumir journald.

## Principio

El script se puede ejecutar repetidamente:

- Si Wazuh Agent ya existe, no reinstala ni toca `/var/ossec`.
- Si falta un componente, lo agrega.
- Si ya existe y está correcto, lo conserva.
- Si encuentra un estado inesperado, informa y termina.
- Cada cambio importante tiene una validación.

## Wazuh Agent

Valores iniciales:

```text
Manager : wazuh.orangebox.cl
Grupo   : OrangeBox
Nombre  : $HOSTNAME
```

El script pregunta si están correctos y permite modificarlos.

La contraseña de enrolamiento no se guarda en Git. Puede entregarse con:

```bash
WAZUH_REGISTRATION_PASSWORD='PASSWORD' ./wazuh.install.rhel.sh
```

o introducirse de forma interactiva. Nunca se muestra.

La instalación usa las variables de despliegue documentadas por Wazuh, incluyendo `WAZUH_MANAGER`, `WAZUH_REGISTRATION_SERVER`, `WAZUH_REGISTRATION_PASSWORD`, `WAZUH_AGENT_NAME` y `WAZUH_AGENT_GROUP`.

Después se comprueba:

- paquete instalado;
- `client.keys`;
- servicio activo.

## Who-Data y FIM

La configuración compartida de `configuration/agents/default/agent.conf` utiliza `whodata="yes"` en rutas críticas.

En Linux, Wazuh utiliza el proveedor `audit` por defecto para Who-Data. El endpoint debe disponer del subsistema Audit para obtener usuario y proceso asociados a los cambios de FIM.

El instalador actual no cambia la política de Audit ni fuerza una PKI de agentes: su responsabilidad sigue siendo instalar el agente y preparar el logging de firewall. La presencia y política de `auditd` debe validarse en los endpoints donde se requiera trazabilidad Who-Data.

No se fuerza `ssl_verify_host` ni la verificación de certificados de agentes desde este instalador. Esa funcionalidad requiere una arquitectura completa de CA y certificados por agente.

## `/var/ossec`

El flujo de instalación nueva crea un LV de **1 GiB (1 GB)** llamado `wazuh`. El Volume Group elegido debe tener al menos 1 GiB libre; si no existe uno suficiente, ese paso falla sin elegir un VG insuficiente.

El script nunca borra contenido existente de `/var/ossec`.

## Firewall

Aplica la precedencia:

```text
Shorewall > firewalld > iptables
```

### Shorewall

Si Shorewall está instalado, el instalador utiliza `/etc/shorewall/rules`, valida la configuración con `shorewall check` y reinicia Shorewall cuando la regla OrangeBox fue modificada.

### firewalld

Si Shorewall no está instalado y firewalld está activo:

- usa `firewall-cmd --direct`;
- agrega la regla TCP SYN OrangeBox;
- la marca como permanente;
- recarga y valida.

Si no hay Shorewall ni firewalld activo:

- usa iptables;
- evita localhost;
- aplica limitación de 20 eventos/s y burst 40;
- en EL7+ administra las reglas OrangeBox mediante `orangebox-iptables.service`, vinculado al ciclo de vida de `wazuh-agent`;
- en EL6 utiliza la persistencia de `/etc/sysconfig/iptables`.

La regla solamente registra; no bloquea por sí misma.

Las reglas Wazuh asociadas realizan la correlación y, cuando corresponde, pueden ejecutar `firewall-drop`.

## rsyslog y logrotate

Estos componentes se configuran **solo en EL6**.

Prefijo:

```text
ORANGEBOX-FW:
```

Archivo:

```text
/var/log/orangebox-firewall.log
```

Logrotate:

```text
/etc/logrotate.d/orangebox-firewall
```

Configuración:

```text
daily
rotate 0
missingok
notifempty
copytruncate
```

No se conservan logs rotados.

## Journald

En EL7+ el script no agrega reglas de rsyslog ni crea archivos auxiliares para OrangeBox.

La fuente del evento es el mensaje `ORANGEBOX-FW:` generado por el kernel/iptables y registrado directamente en journald.

## Wazuh y la detección de red

En EL6 el agente recibe el log desde `/var/log/orangebox-firewall.log`.

En EL7+ el instalador utiliza journald para el logging local del firewall; la recolección de journald debe estar explícitamente habilitada en la configuración del agente para que las reglas de red reciban esos eventos.

Las reglas OrangeBox asociadas están en:

```text
configuration/rules/orangebox-firewall.xml
```

Actualmente:

- `10450`: señal de TCP SYN usada para correlación sin generar alertas individuales.
- `10453`: 12 SYN en 90 segundos, misma IP origen y diferentes puertos destino.
- `10454`: 60 SYN en 10 segundos desde la misma IP y hacia el mismo puerto destino.
- `10455`: 200 IPs origen diferentes en 10 segundos hacia el mismo puerto destino.

`10453` y `10454` tienen `firewall-drop` asociado. `10455` queda como detección distribuida sin bloqueo automático de una IP individual.

## Futuros componentes

Toda nueva dependencia del agente para Wazuh se incorpora a este script siguiendo el mismo patrón:

```text
detectar -> agregar si falta -> validar -> informar error
```

Mantener el script simple es una prioridad.

## Regla de oro

**No duplicar. No adivinar. Validar cada cambio.**
