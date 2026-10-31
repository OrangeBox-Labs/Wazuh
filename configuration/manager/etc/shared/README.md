# Perfiles compartidos de agentes

Este directorio contiene los archivos `agent.conf` que el Manager distribuye a los agentes según el grupo Wazuh al que pertenecen.

## Perfiles disponibles

- **`default/`** — política base de FIM y monitoreo de integridad.
- **`cpanel/`** — controles específicos para cPanel/CloudLinux.
- **`zimbra/`** — controles específicos para Zimbra/Carbonio.
- **`webserver/`** — controles específicos para servidores web.

Cada archivo funcional `agent.conf` debe mantenerse junto a su documentación `agent.md`. El perfil común se aplica desde el grupo `default`; los perfiles específicos se distribuyen mediante los grupos Wazuh correspondientes.

## Asignación y excepciones

La pertenencia a un perfil se administra mediante los grupos de agentes de Wazuh. **No existe una CDB `orangebox-agent-profiles` en este repositorio** y no debe documentarse ni desplegarse como dependencia.

Las CDB de `configuration/manager/etc/lists/` cumplen otra función: entregan contexto a reglas concretas, por ejemplo las listas dinámicas de agentes cPanel, DNS y Zimbra. No reemplazan la asignación de configuración compartida.

## Criterio operativo

La configuración de agentes debe recopilar la evidencia necesaria para las reglas sin convertir FIM en una fuente indiscriminada de ruido. Cada cambio de perfil debe revisarse junto con las reglas que consumen sus eventos y con las CDB de excepciones que correspondan.
