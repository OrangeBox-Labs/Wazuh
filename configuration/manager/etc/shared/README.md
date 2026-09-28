# Agents

Configuraciones distribuidas para los agentes Wazuh.

## Perfiles

- **`default/`** — política base de FIM y monitoreo de integridad utilizada como configuración compartida.
- **`cpanel/`** — etiqueta y documentación del perfil funcional cPanel.
- **`zimbra/`** — etiqueta y documentación del perfil funcional Zimbra/Carbonio.

Cada perfil debe mantener su archivo funcional acompañado de documentación técnica.

Los perfiles no contienen por sí mismos las whitelists de reglas. La relación hostname -> perfil vive en `configuration/manager/etc/lists/orangebox-agent-profiles`, mientras que el grupo Wazuh distribuye la etiqueta funcional al endpoint.

## Criterio

La configuración de agentes debe recopilar la evidencia necesaria para las reglas sin convertir el FIM en una fuente indiscriminada de ruido.

Los cambios de perfil deben mantenerse coordinados con el ruleset y con la CDB.