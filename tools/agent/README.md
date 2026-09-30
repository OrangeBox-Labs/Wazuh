# OrangeBox Wazuh Agent

## Unico instalador

El Agent se instala y mantiene con **un solo instalador**. No hay scripts secundarios que deban ejecutarse manualmente.

Ejecuta como root:

```bash
cd tools/agent
./install.sh
```

El instalador pregunta si el servidor es **cPanel/CSF** y adapta la instalación. Antes de modificar componentes existentes, detecta qué está instalado y reutiliza lo que ya está correcto. Los cambios se aplican de forma idempotente: no duplica reglas ni reemplaza configuraciones existentes de forma ambigua.

## Plataformas soportadas

El instalador soporta **Enterprise Linux 6, 7, 8, 9 y 10**, incluyendo las distribuciones compatibles con estas versiones de EL.

El backend de logging del firewall se adapta a la versión:

- **EL 6:** iptables -> rsyslog -> `/var/log/orangebox-firewall.log` -> Wazuh.
- **EL 7+ :** iptables -> journald -> Wazuh.

Si la versión de Enterprise Linux no es 6, 7, 8, 9 o 10, el instalador se detiene.

## Linux normal

Para servidores Linux sin cPanel:

- instala el **Wazuh Agent oficial** desde el repositorio de Wazuh;
- usa `/var/ossec`;
- prepara LVM para `/var/ossec` cuando corresponde;
- monta `/var/ossec` con `exec,nosuid,nodev`;
- registra y enrola el agente en el Manager;
- configura el firewall OrangeBox según el firewall existente;
- normaliza auditd;
- instala y valida YARA;
- descarga y valida el ruleset oficial **Yara-Rules**;
- instala la integración FIM -> YARA;
- instala la cuarentena Active Response;
- instala la actualización automática del ruleset;
- ejecuta las verificaciones finales.

Si `/var/ossec` ya está correctamente configurado, no lo recrea. Si existe contenido, lo preserva antes de preparar LVM y lo restaura después.

## cPanel / CSF

Para servidores cPanel/CSF:

- instala el **RPM Wazuh Agent OrangeBox OPT** incluido en este directorio;
- usa `/opt/ossec`;
- integra el firewall con **CSF**;
- mantiene el mismo modelo de auditd;
- instala el mismo motor YARA;
- usa el mismo ruleset Yara-Rules;
- instala la misma integración FIM -> YARA;
- instala la misma cuarentena;
- ejecuta las mismas validaciones finales.

El RPM OPT se usa específicamente para este escenario; no se sustituye por el RPM estándar de Wazuh.

Si el servidor usa **Imunify/CloudLinux**, el instalador contempla las diferencias de disponibilidad de paquetes y evita habilitar repositorios adicionales innecesariamente. Cuando corresponde, instala YARA mediante el mecanismo de fallback definido para esa plataforma.

## Enrolamiento

Durante la instalación se muestra y confirma:

- nombre del agente;
- Manager;
- grupo base;
- grupos adicionales;
- ubicación del Agent;
- tipo de instalación.

El nombre del agente se obtiene del FQDN disponible y puede corregirse manualmente durante el proceso. La password de enrolamiento se solicita de forma oculta cuando no está definida.

Al finalizar, el instalador habilita e inicia `wazuh-agent` y verifica que quede activo.

---

## Firewall OrangeBox

El instalador detecta el firewall disponible y aplica la integración correspondiente.

### Shorewall

En servidores con Shorewall, la cadena `ORANGEBOX-FW` se mantiene mediante un bloque idempotente en:

```text
/etc/shorewall/started
```

No se utilizan **Actions de Shorewall**.

La integración:

- crea o reutiliza la cadena `ORANGEBOX-FW`;
- registra TCP SYN a **20 eventos/s**, burst **40**;
- conserva un `RETURN` para el tráfico desde la IP pública propia hacia la IP privada propia;
- conecta la cadena al INPUT del firewall;
- no bloquea tráfico por sí misma;
- elimina la regla OrangeBox antigua de `/etc/shorewall/rules` para evitar doble logging;
- valida la configuración con `shorewall check`;
- reinicia Shorewall solo cuando corresponde.

Los archivos modificados se respaldan antes de cambios estructurales.

### Otros firewalls

El instalador mantiene el mismo objetivo de logging OrangeBox cuando el servidor utiliza el mecanismo de firewall soportado por esa instalación. La integración no convierte el firewall en un mecanismo de bloqueo: **el bloqueo de IOC se realiza mediante Active Response cuando una regla de Wazuh lo solicita**.

---

## auditd

El instalador normaliza la configuración de auditd en:

```text
/etc/audit/rules.d/orangebox-wazuh.rules
```

La lógica es idempotente:

- detecta reglas OrangeBox existentes;
- migra la implementación OrangeBox antigua cuando corresponde;
- elimina duplicados;
- conserva una única definición administrada por OrangeBox;
- genera las reglas necesarias para **ejecución de archivos** y **reconocimiento/ejecución privilegiada**;
- valida la configuración antes de considerarla instalada;
- recarga auditd cuando corresponde.

No se agregan copias de las mismas reglas cada vez que se ejecuta el instalador.

---

## YARA

YARA se instala y valida directamente en el cliente.

El instalador:

1. comprueba si YARA ya existe;
2. instala solo las dependencias que faltan;
3. detecta la ruta del binario;
4. genera `orangebox-yara.sh`;
5. descarga el ruleset oficial **Yara-Rules**;
6. valida los índices `webshells_index.yar` y `malware_index.yar`;
7. obtiene y registra el commit exacto instalado;
8. reemplaza el ruleset anterior solo después de validarlo;
9. fija propietario y permisos;
10. configura actualización automática diaria;
11. valida nuevamente el updater generado.

El runtime se crea directamente en:

```text
<WAZUH_HOME>/active-response/bin/orangebox-yara.sh
```

No se copia desde el repositorio y **no requiere rsync**.

El instalador también crea:

```text
<WAZUH_HOME>/active-response/bin/orangebox-quarantine.py
```

Este script implementa la cuarentena para la regla correspondiente, verifica SHA-256, conserva evidencia y falla de forma segura si el archivo cambia durante el proceso.

El ruleset queda bajo:

```text
<WAZUH_HOME>/active-response/bin/yara/rules/yara-rules
```

y mantiene metadata con:

```text
YARA-RULES-COMMIT
YARA-RULES-REPOSITORY
YARA-RULES-BRANCH
```

La actualización automática se ejecuta diariamente a las **03:17** y conserva el ruleset anterior si la nueva versión no valida.

---

## Integración FIM -> YARA

El flujo no depende de un script instalado manualmente desde el repositorio.

El Agent recibe la configuración correspondiente desde el Manager y, cuando FIM detecta el evento definido para análisis:

```text
FIM
  -> regla/Active Response de Wazuh
  -> orangebox-yara.sh
  -> YARA-Rules
  -> alerta Wazuh
  -> cuarentena cuando corresponde
```

Los ejecutables del Agent son generados por `install.sh`. La configuración que determina **cuándo** se ejecutan las respuestas pertenece al Manager.

No existe una copia de estos scripts bajo `configuration/agent/`.

---

## Verificación final

El instalador no termina simplemente porque los comandos de instalación hayan devuelto cero.

Comprueba, entre otros puntos:

- Wazuh Agent instalado;
- `ossec.conf` presente;
- Agent activo;
- `/var/ossec` correctamente montado cuando aplica;
- `orangebox-yara.sh` presente y ejecutable;
- `orangebox-quarantine.py` presente y ejecutable;
- sintaxis del runtime YARA;
- sintaxis del runtime Python;
- reglas Yara-Rules válidas;
- metadata del ruleset;
- backend de logging del firewall;
- log/logrotate en EL6;
- journald en EL7+.

Si una comprobación crítica falla, el instalador termina con error y muestra qué componente debe revisarse.

## Idempotencia

El instalador está pensado para ejecutarse nuevamente sobre un servidor ya instalado.

En una segunda ejecución:

- no duplica reglas de firewall;
- no duplica reglas de auditd;
- no reinstala innecesariamente componentes que ya están correctos;
- reutiliza LVM existente;
- conserva configuraciones válidas;
- corrige componentes incompletos o inconsistentes;
- actualiza YARA cuando corresponde;
- vuelve a validar el estado final.

**No hay que ejecutar scripts secundarios.** El instalador es el punto único de instalación, corrección y validación del Agent.
