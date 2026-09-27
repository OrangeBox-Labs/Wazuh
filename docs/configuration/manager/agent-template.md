# Plantilla base para grupos de agentes

## `manager/agent-template.conf`

Este archivo es la plantilla minima que debe existir en el Wazuh Manager como:

```text
/var/ossec/etc/shared/agent-template.conf
```

Wazuh utiliza esta plantilla al crear un nuevo Agent Group para inicializar el `agent.conf` del grupo. La documentación de Wazuh establece que cada grupo posee un `agent.conf` bajo `/var/ossec/etc/shared/<grupo>/`. citeturn644657search0turn644657search1

### Contenido

La plantilla debe permanecer deliberadamente vacia de politica funcional:

```xml
<agent_config>
  <!-- Shared agent configuration here -->
</agent_config>
```

No debe contener FIM, labels, reglas, whitelists ni Active Response.

### Motivo

El Manager necesita una plantilla base para poder crear el `agent.conf` inicial de un grupo. Si `/var/ossec/etc/shared/agent-template.conf` no existe, la API/Dashboard puede fallar al crear el grupo.

### Instalación en un Manager existente

```bash
install -o wazuh -g wazuh -m 0640 \
  configuration/manager/agent-template.conf \
  /var/ossec/etc/shared/agent-template.conf
```

Validar:

```bash
test -r /var/ossec/etc/shared/agent-template.conf && echo 'agent-template.conf OK'
```

Después de esto se puede crear el grupo con Dashboard/API o mediante:

```bash
/var/ossec/bin/agent_groups -a -g <grupo>
```

Las configuraciones específicas permanecen separadas por grupo, por ejemplo:

```text
/var/ossec/etc/shared/cpanel/agent.conf
/var/ossec/etc/shared/zimbra/agent.conf
```

## Regla de arquitectura

```text
agent-template.conf
        ↓
crear grupo
        ↓
<grupo>/agent.conf
        ↓
perfil funcional
        ↓
agentes asignados
```

El template no debe utilizarse para propagar configuración común accidentalmente.