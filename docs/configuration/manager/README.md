# Manager

Configuración global del Wazuh Manager.

## Archivos

- **`ossec.conf`** — configuración principal del Manager, incluyendo alertas, correo, módulos, syscheck, indexer, autenticación de agentes e integraciones.
- **`ossec.md`** — documentación técnica del archivo y de las decisiones de configuración.

## Criterio

El Manager es el punto donde convergen los eventos de los agentes, los decoders/reglas nativos y las reglas OrangeBox. Su configuración debe mantenerse separada de la política distribuida de agentes y de la lógica de detección.

Cuando una funcionalidad requiere cambios tanto en Manager como en agentes, la documentación debe describir explícitamente esa dependencia.


## Active Response: port scan

La regla OrangeBox `10453` puede activar `firewall-drop` localmente en el agente que origina la alerta. El bloqueo utiliza la funcionalidad Active Response de Wazuh y tiene un timeout de 3600 segundos.

La configuración se define en el `ossec.conf` del manager. Wazuh incluye `firewall-drop` como script de Active Response para Linux/Unix y utiliza la IP `srcip` del evento para aplicar el bloqueo. citeturn710374search0turn710374search8

Las exclusiones de IP de Active Response se gestionan mediante las listas globales de `white_list`. OrangeBox ya mantiene allí las direcciones internas autorizadas.
