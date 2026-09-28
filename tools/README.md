# Herramientas de Wazuh

Scripts operativos para instalar y validar componentes.

- `wazuh.install.rhel.sh`: instala el agente Linux.
- `wazuh.install.cpanel.sh`: instala el agente OrangeBox/OPT.
- `tools/orangebox-yara/install-orangebox-yara.sh`: instala el runtime YARA y las firmas oficiales.
- `verify-deployed-config.sh`: valida el espejo del Manager, los artefactos de agente desde el source del repo y, con `--agent`, los runtimes realmente desplegados en el agente contra esos mismos sources.
- `update-orangebox-ioc-lists.sh`: actualiza las listas IOC y reinicia Wazuh solo cuando hubo cambios; usa lock para evitar ejecuciones simultáneas.
- `update-orangebox-geoip.sh`: actualiza las bases GeoIP DB-IP Lite locales y conserva la versión vigente ante errores.
- `install-orangebox-geoip.sh`: instala el updater, crea el cron diario y ejecuta la primera actualización.
- `check-orangebox-wazuh.sh`: realiza un chequeo simple de salud del stack.
- `install-orangebox-exec-audit.sh`: configura auditd para detectar ejecuciones desde directorios temporales delicados.

Las firmas YARA no viven en el repositorio OrangeBox: se descargan desde `Yara-Rules/rules` usando un commit aprobado.


## Documentación

Cada herramienta funcional debe mantener su documentación junto al script, con el mismo nombre base: `script.sh` + `script.md` o `script.py` + `script.md`.
