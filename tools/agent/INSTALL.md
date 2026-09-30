# Instalación del agente Wazuh OrangeBox

El despliegue completo se realiza con un único instalador:

```bash
cd tools/agent
./install.sh
```

El instalador pregunta si el servidor es cPanel/CSF.

## Flujo

1. Detecta si Wazuh ya está instalado.
2. Si falta, instala el agente normal o el RPM OPT de cPanel.
3. Configura el almacenamiento `/var/ossec` en Linux normal.
4. Verifica/configura el firewall OrangeBox.
5. Verifica/configura auditd.
6. Verifica/configura YARA y sus dependencias.
7. Genera `orangebox-yara.sh` y `orangebox-quarantine.py` directamente en el cliente.
8. Descarga y valida el ruleset oficial Yara-Rules.
9. Reinicia/valida el agente.
10. Ejecuta las validaciones finales.

El proceso es idempotente: una segunda ejecución no debería duplicar reglas ni archivos de configuración que ya estén correctamente instalados.

## Firewall OrangeBox

El instalador aplica la precedencia **Shorewall > firewalld > iptables**.

### Shorewall

Cuando Shorewall está instalado, el instalador no utiliza `rules` ni Actions para implementar la cadena OrangeBox. Agrega de forma idempotente un bloque marcado en:

```text
/etc/shorewall/started
```

El bloque se ejecuta después de que Shorewall haya creado su firewall y:

- crea la cadena `ORANGEBOX-FW` si no existe;
- reconstruye solamente esa cadena para evitar duplicados;
- detecta dinámicamente la IP privada y la IP pública en cada arranque/reinicio de Shorewall;
- permite con `RETURN` el tráfico TCP SYN desde la IP pública del propio servidor hacia su IP privada;
- registra TCP SYN con `LOG` limitado a **20 eventos/s, burst 40**;
- termina con `RETURN` para no bloquear tráfico por sí mismo;
- conecta `INPUT` con `ORANGEBOX-FW` una sola vez.

Si existe la regla OrangeBox antigua en `/etc/shorewall/rules`, el instalador la retira después de respaldar el archivo. La configuración se valida con `shorewall check` antes de aplicar el reinicio.

La presencia del marcador:

```text
# BEGIN ORANGEBOX WAZUH FIREWALL
```

se utiliza para que una segunda ejecución no vuelva a insertar el bloque.

## auditd

El instalador mantiene un único archivo canónico:

```text
/etc/audit/rules.d/orangebox-wazuh.rules
```

Las reglas cubren:

- ejecución `execve` desde `/tmp`, `/var/tmp` y `/dev/shm` con la clave `orangebox_exec`;
- ejecución de herramientas de scanner y reconocimiento que estén realmente instaladas, con la clave `audit-wazuh-c`;
- arquitecturas `b64` y `b32` cuando el kernel/audit las soporte.

Las instalaciones antiguas que todavía tengan `99-orangebox-exec.rules` con reglas OrangeBox se respaldan y migran al archivo canónico para evitar el error de reglas duplicadas de `augenrules`.

En Enterprise Linux 10 se instala `audit-rules` cuando corresponde. Después de cargar las reglas, se valida que las claves OrangeBox estén activas y se reinicia Wazuh para consumir `/var/log/audit/audit.log`.

## cPanel

El RPM OPT está en el mismo directorio:

```text
tools/agent/wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

El instalador lo utiliza únicamente cuando se selecciona cPanel.

## YARA

El script de integración se genera durante la instalación en:

```text
/var/ossec/active-response/bin/orangebox-yara.sh
```

o, en cPanel:

```text
/opt/ossec/active-response/bin/orangebox-yara.sh
```

No se requiere copiar scripts ni ejecutar otro instalador YARA.
