# Herramientas de Wazuh

Scripts operativos para instalar y validar componentes.

- `wazuh.install.rhel.sh`: instala el agente Linux.
- `wazuh.install.cpanel.sh`: instala el agente OrangeBox/OPT.
- `install-orangebox-yara.sh`: instala el runtime YARA del árbol `configuration/agents/common/`.
- `verify-deployed-config.sh`: valida el espejo del Manager o, con `--agent`, el runtime YARA del agente.
- `update-orangebox-ioc-lists.sh`: actualiza las listas IOC y reinicia Wazuh solo cuando hubo cambios.
- `check-orangebox-wazuh.sh`: realiza un chequeo simple de salud del stack.

El índice manual de YARA está en `tools/yara/webshells_index.yar`.


## Documentación

Cada herramienta funcional debe mantener su documentación junto al script, con el mismo nombre base: `script.sh` + `script.md` o `script.py` + `script.md`.
