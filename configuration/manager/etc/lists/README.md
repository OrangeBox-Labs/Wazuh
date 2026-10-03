# CDB y sincronización de agentes OrangeBox

Este directorio contiene listas CDB utilizadas directamente por las reglas del Wazuh Manager.

Las CDB se dividen en dos tipos:

- **estáticas**: se mantienen en el repositorio y se despliegan sin cambios;
- **dinámicas**: se generan desde grupos Wazuh y no deben editarse manualmente.

## CDB estáticas

### `orangebox-network-recon-programs`

Define los comandos que cuentan como reconocimiento de red para las correlaciones `10612` y `10614`.

Formato:

```text
comando:network_recon
```

Incluye utilidades de consulta de red como `ip`, `ss`, `netstat`, `lsof`, `route`, `arp`, `ifconfig` y `nmcli`.

La lista debe estar declarada en el bloque `<ruleset>` de `manager/etc/ossec.conf`.

### CDB operacionales

Las CDB adicionales pueden contener orígenes de red o identidades autorizadas para una excepción concreta. Su alcance debe quedar documentado en la regla que las utiliza.

Una CDB operacional no debe convertirse en una whitelist global de usuario, directorio o shell.

## CDB dinámicas por grupo Wazuh

La fuente de verdad es la pertenencia del agente al grupo Wazuh. El hostname no se mantiene manualmente en una segunda lista.

### `orangebox-cpanel-agents`

Representa el grupo Wazuh `cpanel`.

El sincronizador es:

```text
configuration/manager/bin/update-orangebox-cpanel-agents.sh
```

y su cron:

```text
configuration/manager/etc/cron.d/orangebox-cpanel-agents
```

Consulta `agent_groups -l -g cpanel`, genera hostname FQDN y hostname corto y actualiza la CDB solo cuando cambia.

### `orangebox-zimbra-agents`

Representa el grupo Wazuh `zimbra`.

Este contexto cubre Zimbra y Carbonio CE.

El sincronizador es:

```text
configuration/manager/bin/update-orangebox-zimbra-agents.sh
```

y su cron:

```text
configuration/manager/etc/cron.d/orangebox-zimbra-agents
```

Consulta `agent_groups -l -g zimbra` y genera hostname FQDN y hostname corto.

Las reglas de autenticación y comportamiento pueden usar esta CDB para reconocer el contexto del endpoint, pero el grupo por sí solo nunca autoriza una operación privilegiada: la regla debe exigir además identidad, comando o contexto exacto.

Las CDB dinámicas no deben editarse manualmente.

## Declaración en `ossec.conf`

Toda CDB usada por una regla debe estar declarada en el bloque `<ruleset>` de `/var/ossec/etc/ossec.conf`.

Ejemplos:

```xml
<list>etc/lists/orangebox-network-recon-programs</list>
<list>etc/lists/orangebox-cpanel-agents</list>
<list>etc/lists/orangebox-zimbra-agents</list>
```

Si una regla referencia una CDB no declarada o inexistente, `wazuh-analysisd -t` puede registrar el warning `(7616)` y omitir la regla.

## Regla de seguridad

Una excepción operacional debe combinar contexto del endpoint con identidad y/o comando o condición exacta:

```text
grupo / contexto del endpoint
        +
usuario o identidad cuando corresponda
        +
comando o condición exacta
        =
excepción
```

No convertir una excepción puntual en una whitelist global.

## Validación

Después de modificar reglas o CDB:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Para validar la sincronización:

```bash
/var/ossec/bin/update-orangebox-cpanel-agents.sh
/var/ossec/bin/update-orangebox-zimbra-agents.sh
```

El verificador `tools/verify-deployed-config.sh` comprueba además que las CDB requeridas por las reglas existan y estén declaradas.

## IDs de reglas

Agregar una IP o agente a una CDB existente no requiere un nuevo SID. Cuando realmente haga falta una regla nueva, usar un ID libre del rango `20000-29999` y comprobar que no exista en otro XML.
