# OrangeBox Wazuh Agent

## Unico instalador

Ejecuta como root:

```bash
cd tools/agent
./install.sh
```

El instalador pregunta si el servidor es **cPanel/CSF**.

### Linux normal

- Wazuh Agent oficial.
- `/var/ossec`.
- LVM para `/var/ossec` cuando corresponde.
- Firewall OrangeBox.
- auditd.
- YARA.
- ruleset oficial Yara-Rules.
- integración FIM -> YARA.

### cPanel / CSF

- RPM OrangeBox OPT incluido en este directorio.
- `/opt/ossec`.
- integración CSF.
- mismo firewall OrangeBox.
- mismo auditd.
- mismo YARA.
- mismo flujo de validación.

El instalador detecta qué componentes ya existen y **solo crea o corrige lo que falta**.

No hay que ejecutar scripts secundarios.

## Firewall y auditd

En servidores con Shorewall, la cadena `ORANGEBOX-FW` se mantiene mediante un bloque idempotente en `/etc/shorewall/started`. No se utilizan Actions de Shorewall para esta integración. La cadena registra TCP SYN a **20/s, burst 40**, conserva una excepción `RETURN` para el tráfico de la propia IP pública hacia la IP privada y no realiza bloqueos por sí misma.

El instalador también normaliza las reglas de `auditd` en `/etc/audit/rules.d/orangebox-wazuh.rules`, migrando la implementación OrangeBox antigua cuando existe y evitando duplicados al regenerar las reglas de ejecución temporal y reconocimiento.

## YARA

El instalador crea directamente en el cliente:

```text
<WAZUH_HOME>/active-response/bin/orangebox-yara.sh
<WAZUH_HOME>/active-response/bin/orangebox-quarantine.py
```

No se copian estos scripts desde el repositorio ni se requiere rsync. La versión bajo `configuration/agent/active-response/bin/` mantiene la misma estructura del runtime y sirve como referencia versionada.

Las reglas se descargan desde el repositorio oficial Yara-Rules y se fijan al commit aprobado por el instalador.
