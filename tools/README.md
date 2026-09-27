# Herramientas de Wazuh

Scripts operativos para instalar y validar componentes.

- `wazuh.install.rhel.sh`: instala el agente Linux.
- `wazuh.install.cpanel.sh`: instala el agente OrangeBox/OPT.
- `install-orangebox-yara.sh`: instala el runtime YARA del árbol `configuration/agents/common/`.
- `verify-deployed-config.sh`: valida el espejo del Manager o, con `--agent`, el runtime YARA del agente.

El índice manual de YARA está en `tools/yara/webshells_index.yar`.
