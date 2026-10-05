# Herramientas de Wazuh OrangeBox

## Instalador unificado de agentes

Existe un único instalador:

```bash
cd tools/agent
./install.sh
```

Al ejecutarlo pregunta si el servidor es **cPanel/CSF**.

- **Linux normal:** instala el Wazuh Agent oficial y usa `/var/ossec`.
- **cPanel:** instala el RPM OrangeBox OPT y usa `/opt/ossec`.

Después, el mismo flujo verifica y configura de forma idempotente:

1. Wazuh Agent.
2. Firewall OrangeBox.
3. auditd para monitoreo de ejecución.
4. YARA y sus dependencias.
5. Ruleset oficial Yara-Rules.
6. Active Response YARA y cuarentena, generados directamente por el instalador del agente.
7. Validaciones finales y arranque del agente.

**No hay que ejecutar instaladores secundarios.**

El RPM OPT requerido para cPanel está junto al instalador:

```text
tools/agent/
├── install.sh
├── README.md
├── INSTALL.md
└── wazuh-agent_4.14.8-0_x86_64_OPT.rpm
```

## Fallos y resumen del instalador

El instalador unificado ejecuta cada etapa de forma aislada. Un fallo en Firewall, Logging, Auditd, YARA o Cuarentena no detiene las etapas posteriores. Al final muestra un resumen `[OK]` / `[ERROR]` y devuelve `1` si alguna etapa falló.

## Firewall Shorewall

Cuando Shorewall está instalado, el instalador mantiene la integración OrangeBox en `/etc/shorewall/started`. El bloque está delimitado por `BEGIN/END ORANGEBOX WAZUH FIREWALL`, se agrega una sola vez y se vuelve a ejecutar con cada ciclo de arranque/reinicio de Shorewall.

La cadena `ORANGEBOX-FW` registra TCP SYN a 20 eventos/s con burst 40, incluye la excepción de tráfico desde la IP pública del servidor hacia su IP privada y termina en `RETURN`. La regla OrangeBox antigua de `/etc/shorewall/rules` se elimina de forma controlada durante la migración.

## auditd

Las reglas OrangeBox de ejecución usan `/etc/audit/rules.d/70-orangebox-wazuh.rules` como archivo canónico. El instalador migra `99-orangebox-exec.rules` si contiene reglas OrangeBox, genera reglas para `/tmp`, `/var/tmp`, `/dev/shm` y para ejecutables de scanner/reconocimiento realmente presentes, y valida la carga con `augenrules`/`auditctl`. Para Whodata instala `audispd-plugins` y valida `audisp-af_unix`; Wazuh administra su propio `/etc/audit/plugins.d/af_wazuh.conf` y el `af_unix.conf` genérico se deja sin activar.

## Herramientas operativas

Estas herramientas no forman parte del despliegue base del agente:

- `check-orangebox-wazuh.sh`
- `verify-deployed-config.sh`
- `install-orangebox-geoip.sh`
- `update-orangebox-geoip.sh`
- `update-orangebox-ioc-lists.sh`
- `update-orangebox-backuppc.sh`
- `update-orangebox-cpanel-agents.sh`
- `update-orangebox-zimbra-agents.sh`

## Build del RPM

`packages/agent/build.sh` conserva el proceso para construir el RPM OPT. El artefacto de producción se copia al directorio `tools/agent/` para que el instalador sea autosuficiente.

## Authd

No existe un instalador de `authd` para los endpoints en este repo. El enrollment del agente se realiza mediante la configuración de Wazuh; `wazuh-authd` pertenece al Manager.

## Permisos

`verify-ossec-permissions.sh` revisa y, con `--fix`, repara los dueños, grupos y permisos definidos para `/var/ossec`. Por defecto solo revisa.

## Salud y despliegue

- `check-orangebox-wazuh.sh`: comprueba la salud del stack. No modifica nada.
- `verify-deployed-config.sh`: compara Git contra `/var/ossec`, incluyendo reglas desplegadas y CDB requeridas por esas reglas. No modifica nada.
- `verify-ossec-permissions.sh`: revisa o repara permisos. Solo cambia archivos con `--fix`.

## Depuración de reglas y Active Response

Guía práctica para probar eventos, revisar `archives.json` y `alerts.json`, usar `wazuh-logtest` y seguir una alerta hasta correo o Active Response:

- [tools/WAZUH-RULE-DEBUG.md](WAZUH-RULE-DEBUG.md)


## Sincronización de grupos del Manager

Las excepciones de aplicaciones usan grupos Wazuh como fuente de verdad.

```text
cpanel -> update-orangebox-cpanel-agents.sh -> orangebox-cpanel-agents
zimbra -> update-orangebox-zimbra-agents.sh -> orangebox-zimbra-agents
```

Los sincronizadores generan hostname FQDN y hostname corto y mantienen las CDB sin una lista manual de agentes. Se ejecutan mediante cron cada 10 minutos fuera de la ventana de rotación de medianoche.

No mantener listas manuales de hostnames para estos perfiles.
